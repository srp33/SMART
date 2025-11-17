from __future__ import annotations
import os
import uuid
import datetime as dt
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, abort, session
from flask import g
from sqlalchemy import create_engine, text
import fitz  # PyMuPDF
import hashlib

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_DIR = BASE_DIR / "uploads"
IMAGES_DIR = BASE_DIR / "images"

for p in (UPLOAD_DIR, IMAGES_DIR):
    p.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-key"
app.config["DATABASE_URL"] = f"sqlite:///{BASE_DIR / 'app.db'}"

# Support for running behind a reverse proxy with URL prefix
# Set SCRIPT_NAME environment variable to the prefix (e.g., /Annotation_Tool)
# For local development, leave unset or set to empty string
script_name = os.environ.get('SCRIPT_NAME', '')
if script_name:
    # Ensure it starts with / and doesn't end with /
    script_name = '/' + script_name.strip('/')
    app.config['APPLICATION_ROOT'] = script_name
    
    # Create a middleware to inject SCRIPT_NAME into the WSGI environment
    # This handles cases where the proxy may or may not strip the prefix
    class ScriptNameMiddleware:
        def __init__(self, app, script_name):
            self.app = app
            self.script_name = script_name
        
        def __call__(self, environ, start_response):
            # Always set SCRIPT_NAME for url_for to work correctly
            # (Even if proxy strips prefix from PATH_INFO, we need SCRIPT_NAME for URL generation)
            environ['SCRIPT_NAME'] = self.script_name
            
            # Adjust PATH_INFO to remove the prefix if it's present
            # (Some proxies strip it, some don't - handle both cases)
            path_info = environ.get('PATH_INFO', '')
            if path_info.startswith(self.script_name):
                # Remove the prefix and ensure PATH_INFO starts with /
                new_path = path_info[len(self.script_name):]
                if not new_path.startswith('/'):
                    new_path = '/' + new_path
                environ['PATH_INFO'] = new_path
            # If PATH_INFO doesn't start with prefix, assume proxy already stripped it
            # Just ensure PATH_INFO starts with / (it should already)
            elif path_info and not path_info.startswith('/'):
                environ['PATH_INFO'] = '/' + path_info
            
            return self.app(environ, start_response)
    
    app.wsgi_app = ScriptNameMiddleware(app.wsgi_app, script_name)
    
    # Store script_name in app config for use in templates
    app.config['SCRIPT_NAME'] = script_name
else:
    app.config['SCRIPT_NAME'] = ''

# Make SCRIPT_NAME available to all templates
@app.context_processor
def inject_script_name():
    return {'script_name': app.config.get('SCRIPT_NAME', '')}

# Helper function to generate URLs with prefix support
def url_with_prefix(endpoint, **values):
    """Generate URL with prefix support, ensuring SCRIPT_NAME is included.
    Flask's url_for should automatically use SCRIPT_NAME from WSGI environ,
    but we ensure it's there as a fallback."""
    try:
        url = url_for(endpoint, **values)
        script_name = app.config.get('SCRIPT_NAME', '')
        if script_name:
            # Flask should already include SCRIPT_NAME, but check to be sure
            # Remove any existing prefix first to avoid double-prefixing
            if url.startswith(script_name):
                return url  # Already has prefix
            # Ensure URL starts with /, then prepend prefix
            if not url.startswith('/'):
                url = '/' + url
            url = script_name + url
        return url
    except Exception as e:
        # Fallback to url_for if there's an error
        import traceback
        print(f"Error in url_with_prefix: {e}")
        traceback.print_exc()
        return url_for(endpoint, **values)

# --- DB setup (vanilla SQLAlchemy Core for brevity) ---
engine = create_engine(app.config["DATABASE_URL"], future=True)

def init_db():
    with engine.begin() as conn:
        # Users table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,                -- 'teacher' or 'student'
            created_at TEXT NOT NULL
        )"""))
        
        # Documents table - add uploaded_by
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            uploaded_by INTEGER,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )"""))
        
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            page_index INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            FOREIGN KEY(document_id) REFERENCES documents(id)
        )"""))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS annotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL,
            user_id INTEGER,                   -- who made the annotation
            kind TEXT NOT NULL,            -- 'rect' or 'text'
            x REAL NOT NULL,
            y REAL NOT NULL,
            w REAL,                        -- width (rect only)
            h REAL,                        -- height (rect only)
            text TEXT,                     -- text (text only)
            color TEXT,                    -- e.g., '#ff3860'
            created_at TEXT NOT NULL,
            FOREIGN KEY(page_id) REFERENCES pages(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )"""))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reactions (
            page_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,                    -- who made the reaction
            emoji TEXT NOT NULL,               -- e.g., "🤩"
            created_at TEXT NOT NULL,
            PRIMARY KEY(page_id, user_id),
            FOREIGN KEY(page_id) REFERENCES pages(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )"""))
        
        # Document assignments - link documents to students
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS document_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            student_id INTEGER NOT NULL,
            assigned_at TEXT NOT NULL,
            FOREIGN KEY(document_id) REFERENCES documents(id),
            FOREIGN KEY(student_id) REFERENCES users(id),
            UNIQUE(document_id, student_id)
        )"""))

init_db()

def migrate_db():
    """Migrate existing database to add new columns for authentication"""
    with engine.begin() as conn:
        # Check and add uploaded_by to documents table
        try:
            conn.execute(text("SELECT uploaded_by FROM documents LIMIT 1"))
        except Exception:
            # Column doesn't exist, add it
            try:
                conn.execute(text("ALTER TABLE documents ADD COLUMN uploaded_by INTEGER"))
            except Exception:
                pass  # Column might already exist
        
        # Check and add user_id to annotations table
        try:
            conn.execute(text("SELECT user_id FROM annotations LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE annotations ADD COLUMN user_id INTEGER"))
            except Exception:
                pass
        
        # Check and update reactions table structure
        # First check if it has the old structure (page_id as PRIMARY KEY only)
        try:
            result = conn.execute(text("PRAGMA table_info(reactions)"))
            columns = [row[1] for row in result.fetchall()]
            if 'user_id' not in columns:
                # Need to recreate the table with new structure
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS reactions_new (
                        page_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        emoji TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY(page_id, user_id),
                        FOREIGN KEY(page_id) REFERENCES pages(id),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )
                """))
                # Copy existing data if any (assign to user_id 1 if users exist, otherwise NULL)
                try:
                    # Check if users table exists and has any users
                    user_check = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
                    default_user_id = 1 if user_check > 0 else None
                    if default_user_id:
                        conn.execute(text("""
                            INSERT INTO reactions_new (page_id, user_id, emoji, created_at)
                            SELECT page_id, :user_id, emoji, created_at FROM reactions
                        """), {"user_id": default_user_id})
                except Exception:
                    pass
                # Drop old table and rename new one
                conn.execute(text("DROP TABLE reactions"))
                conn.execute(text("ALTER TABLE reactions_new RENAME TO reactions"))
        except Exception:
            pass

# Run migration
migrate_db()

# --- Authentication Helpers ---
def hash_password(password: str) -> str:
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash

def get_current_user():
    """Get current logged in user from session"""
    if 'user_id' not in session:
        return None
    with engine.begin() as conn:
        user = conn.execute(
            text("SELECT id, username, role FROM users WHERE id = :id"),
            {"id": session['user_id']}
        ).first()
    if user:
        return {"id": user.id, "username": user.username, "role": user.role}
    return None

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    """Decorator to require teacher role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'teacher':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    """Decorator to require student role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'student':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Helpers ---
def render_pdf_to_pngs(pdf_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = fitz.open(pdf_path)
    paths = []
    for i, page in enumerate(doc):
        # 150-200 dpi is a sweet spot; scale ~2 gives ~144 dpi
        matrix = fitz.Matrix(2, 2)
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        out_path = out_dir / f"page_{i+1}.png"
        pix.save(out_path.as_posix())
        paths.append(out_path)
    doc.close()
    return paths

# --- Routes ---
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Initial setup - create first teacher account if no users exist"""
    try:
        with engine.begin() as conn:
            try:
                user_count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
                if user_count > 0:
                    # Users already exist, redirect to login
                    return redirect(url_for("login"))
            except Exception:
                # Table doesn't exist yet, that's fine - continue with setup
                pass
    except Exception:
        # Database might not exist, that's fine - continue with setup
        pass
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not username or not password:
            return render_template("setup.html", error="Username and password required")
        
        if password != confirm_password:
            return render_template("setup.html", error="Passwords do not match")
        
        password_hash = hash_password(password)
        
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO users (username, password_hash, role, created_at)
                        VALUES (:username, :password_hash, :role, :created_at)
                    """),
                    {
                        "username": username,
                        "password_hash": password_hash,
                        "role": "teacher",
                        "created_at": dt.datetime.utcnow().isoformat()
                    }
                )
            # Auto-login after setup
            with engine.begin() as conn:
                user = conn.execute(
                    text("SELECT id, username, role FROM users WHERE username = :username"),
                    {"username": username}
                ).first()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for("index"))
        except Exception as e:
            return render_template("setup.html", error="Failed to create account. Please try again.")
    
    return render_template("setup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            return render_template("login.html", error="Username and password required")
        
        with engine.begin() as conn:
            user = conn.execute(
                text("SELECT id, username, password_hash, role FROM users WHERE username = :username"),
                {"username": username}
            ).first()
        
        if user and verify_password(password, user.password_hash):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Invalid username or password")
    
    # If already logged in, redirect to index
    if 'user_id' in session:
        return redirect(url_for("index"))
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    # Redirect to login with prefix support
    return redirect(url_with_prefix("login"))


@app.route("/", methods=["GET"])
def index():
    # Check if any users exist - if not, redirect to setup
    try:
        with engine.connect() as conn:
            # Check if users table exists and has any users
            try:
                result = conn.execute(text("SELECT COUNT(*) FROM users"))
                user_count = result.scalar()
                conn.commit()
                if user_count == 0:
                    return redirect(url_for("setup"))
            except Exception as e:
                # Table doesn't exist yet or error, redirect to setup
                conn.rollback()
                return redirect(url_for("setup"))
    except Exception:
        # Database error, redirect to setup
        return redirect(url_for("setup"))
    
    # If not logged in, redirect to login
    if 'user_id' not in session:
        return redirect(url_for("login"))
    
    user = get_current_user()
    
    with engine.begin() as conn:
        if user['role'] == 'teacher':
            # Teachers see all documents they uploaded (or NULL uploaded_by for legacy docs)
            docs = conn.execute(
                text("""
                    SELECT id, filename, uploaded_at 
                    FROM documents 
                    WHERE uploaded_by = :user_id OR uploaded_by IS NULL
                    ORDER BY uploaded_at DESC
                """),
                {"user_id": user['id']}
            ).all()
        else:
            # Students see all documents (including legacy ones with NULL uploaded_by)
            docs = conn.execute(
                text("""
                    SELECT d.id, d.filename, d.uploaded_at
                    FROM documents d
                    ORDER BY d.uploaded_at DESC
                """)
            ).all()
    
    return render_template("index.html", docs=docs, user=user)

@app.route("/upload", methods=["POST"])
@teacher_required
def upload():
    f = request.files.get("pdf")
    if not f or not f.filename.lower().endswith(".pdf"):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Invalid file format. Please upload a PDF file."}), 400
        return redirect(url_for("index"))
        
    doc_id = uuid.uuid4().hex
    safe_name = f"{doc_id}.pdf"
    pdf_path = UPLOAD_DIR / safe_name
    f.save(pdf_path)

    # Convert to PNGs
    out_dir = IMAGES_DIR / doc_id
    out_dir.mkdir(parents=True, exist_ok=True)
    png_paths = render_pdf_to_pngs(pdf_path, out_dir)
    
    # Prepare response data
    pages_data = []
    
    user = get_current_user()
    
    with engine.begin() as conn:
        # First insert the document
        conn.execute(
            text("""
                INSERT INTO documents (id, filename, uploaded_at, uploaded_by)
                VALUES (:id, :filename, :uploaded_at, :uploaded_by)
            """),
            {
                "id": doc_id, 
                "filename": f.filename, 
                "uploaded_at": dt.datetime.utcnow().isoformat(),
                "uploaded_by": user['id']
            }
        )
        
        # Then insert all pages
        for i, png_path in enumerate(png_paths):
            # Store relative path from the static directory
            rel_path = png_path.relative_to(IMAGES_DIR)
            result = conn.execute(
                text("""
                    INSERT INTO pages (document_id, page_index, image_path)
                    VALUES (:doc_id, :page_index, :image_path)
                    RETURNING id
                """),
                {"doc_id": doc_id, "page_index": i, "image_path": str(rel_path)}
            )
            page_id = result.scalar()
            # Generate image URL with prefix support
            image_url = url_with_prefix('serve_image', rel=str(rel_path))
            pages_data.append({"id": page_id, "index": i, "image_url": image_url})
    
    # Return appropriate response based on request type
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            "doc_id": doc_id,
            "filename": f.filename,
            "pages": pages_data
        })
    
    return redirect(url_with_prefix("document_first_page", doc_id=doc_id))

@app.route("/doc/<doc_id>/first")
@login_required
def document_first_page(doc_id):
    """Redirect to the first page of a document"""
    user = get_current_user()
    if not user:
        return redirect(url_with_prefix('login'))
    
    with engine.begin() as conn:
        # Check access - teachers see their own docs, students can see any teacher-uploaded doc
        if user['role'] == 'teacher':
            doc = conn.execute(
                text("SELECT id, filename FROM documents WHERE id=:id AND (uploaded_by=:user_id OR uploaded_by IS NULL)"), 
                {"id": doc_id, "user_id": user['id']}
            ).one_or_none()
        else:
            # Student - can see any document (including legacy ones)
            doc = conn.execute(
                text("""
                    SELECT d.id, d.filename 
                    FROM documents d
                    WHERE d.id=:id
                """), 
                {"id": doc_id}
            ).one_or_none()
        
        if not doc:
            abort(404)
        
        # Get first page and redirect to it
        first_page = conn.execute(text("""
            SELECT id FROM pages
            WHERE document_id=:id ORDER BY page_index ASC LIMIT 1
        """), {"id": doc_id}).first()
        
        if first_page:
            return redirect(url_with_prefix('page', page_id=first_page.id))
        else:
            # No pages found, show error
            abort(404)

@app.route("/doc/<doc_id>", methods=["GET"])
@login_required
def document(doc_id):
    user = get_current_user()
    
    with engine.begin() as conn:
        # Check access - teachers see their own docs, students can see any teacher-uploaded doc
        if user['role'] == 'teacher':
            doc = conn.execute(
                text("SELECT id, filename FROM documents WHERE id=:id AND (uploaded_by=:user_id OR uploaded_by IS NULL)"), 
                {"id": doc_id, "user_id": user['id']}
            ).one_or_none()
        else:
            # Student - can see any document (including legacy ones)
            doc = conn.execute(
                text("""
                    SELECT d.id, d.filename 
                    FROM documents d
                    WHERE d.id=:id
                """), 
                {"id": doc_id}
            ).one_or_none()
        
        if not doc:
            abort(404)
        
        pages = conn.execute(text("""
            SELECT id, page_index, image_path FROM pages
            WHERE document_id=:id ORDER BY page_index ASC
        """), {"id": doc_id}).all()
    
    return render_template("document.html", doc=doc, pages=pages, user=user)

@app.route("/page/<int:page_id>.json")
@login_required
def page_json(page_id):
    with engine.begin() as conn:
        page = conn.execute(
            text("""
                SELECT p.*, d.id as document_id, d.filename 
                FROM pages p 
                JOIN documents d ON p.document_id = d.id 
                WHERE p.id = :page_id
            """),
            {"page_id": page_id}
        ).first()
        
        if not page:
            abort(404)
        
        # Get annotations for this page - only show current user's annotations
        user = get_current_user()
        annotations = conn.execute(
            text("""
                SELECT id, kind, x, y, w, h, text, color
                FROM annotations 
                WHERE page_id = :page_id AND user_id = :user_id
            """),
            {"page_id": page_id, "user_id": user['id']}
        ).fetchall()
        
        # Convert Row objects to dictionaries
        annotations = [
            {
                "id": a.id,
                "kind": a.kind,
                "x": a.x,
                "y": a.y,
                "w": a.w,
                "h": a.h,
                "text": a.text,
                "color": a.color
            }
            for a in annotations
        ]
        
        # Get total pages in document
        total_pages = conn.execute(
            text("SELECT COUNT(*) FROM pages WHERE document_id = :doc_id"),
            {"doc_id": page.document_id}
        ).scalar()
        
        # Get all page IDs for navigation
        page_ids = conn.execute(
            text("""
                SELECT id, page_index 
                FROM pages 
                WHERE document_id = :doc_id 
                ORDER BY page_index
            """),
            {"doc_id": page.document_id}
        ).fetchall()
        
        # Find current page index
        current_page_index = next((i for i, p in enumerate(page_ids) if p.id == page_id), 0)
        
        # Prepare navigation info
        nav = {
            "current": current_page_index,
            "total": total_pages,
            "has_prev": current_page_index > 0,
            "has_next": current_page_index < total_pages - 1,
            "prev_page_id": page_ids[current_page_index - 1].id if current_page_index > 0 else None,
            "next_page_id": page_ids[current_page_index + 1].id if current_page_index < total_pages - 1 else None,
            "first_page_id": page_ids[0].id if page_ids else None,
            "last_page_id": page_ids[-1].id if page_ids else None
        }
        
        # Generate image URL with prefix support
        image_url = url_with_prefix('serve_image', rel=page.image_path)
        
        return jsonify({
            "id": page.id,
            "document_id": page.document_id,
            "page_index": page.page_index,
            "image_url": image_url,
            "filename": page.filename,
            "annotations": annotations,
            "navigation": nav
        })

@app.route("/page/<int:page_id>")
@login_required
def page(page_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    with engine.begin() as conn:
        # Get page with document info
        page_data = conn.execute(
            text("""
                SELECT p.*, d.id as document_id, d.filename 
                FROM pages p 
                JOIN documents d ON p.document_id = d.id 
                WHERE p.id = :page_id
            """),
            {"page_id": page_id}
        ).first()
        
        if not page_data:
            abort(404)
        
        # Check access - teachers see their own docs, students can see any doc
        if user['role'] == 'teacher':
            doc_check = conn.execute(
                text("SELECT id FROM documents WHERE id=:id AND (uploaded_by=:user_id OR uploaded_by IS NULL)"),
                {"id": page_data.document_id, "user_id": user['id']}
            ).first()
            if not doc_check:
                abort(404)
        
        # Get annotations for this page - only for students
        annotations_list = []
        if user['role'] == 'student':
            annotations = conn.execute(
                text("""
                    SELECT id, kind, x, y, w, h, text, color
                    FROM annotations 
                    WHERE page_id = :page_id AND user_id = :user_id
                """),
                {"page_id": page_id, "user_id": user['id']}
            ).fetchall()
            
            # Convert to list of dicts
            annotations_list = [
                {
                    "id": a.id,
                    "kind": a.kind,
                    "x": a.x,
                    "y": a.y,
                    "w": a.w,
                    "h": a.h,
                    "text": a.text,
                    "color": a.color
                }
                for a in annotations
            ]
        
        # Get reaction for this user (only for students)
        current_emoji = None
        emotion_counts = {}
        
        if user['role'] == 'student':
            reaction = conn.execute(
                text("SELECT emoji FROM reactions WHERE page_id = :pid AND user_id = :user_id"),
                {"pid": page_id, "user_id": user['id']}
            ).first()
            current_emoji = reaction.emoji if reaction else None
        else:
            # For teachers, get emotion counts from all students
            reactions = conn.execute(
                text("""
                    SELECT emoji, COUNT(*) as count
                    FROM reactions 
                    WHERE page_id = :pid
                    GROUP BY emoji
                """),
                {"pid": page_id}
            ).fetchall()
            
            for r in reactions:
                emotion_counts[r.emoji] = r.count
        
        # Get all pages in document for navigation
        all_pages = conn.execute(
            text("""
                SELECT id, page_index 
                FROM pages 
                WHERE document_id = :doc_id 
                ORDER BY page_index
            """),
            {"doc_id": page_data.document_id}
        ).fetchall()
        
        # Find current page index
        current_index = next((i for i, p in enumerate(all_pages) if p.id == page_id), 0)
        prev_page_id = all_pages[current_index - 1].id if current_index > 0 else None
        next_page_id = all_pages[current_index + 1].id if current_index < len(all_pages) - 1 else None
    
    return render_template("page.html", 
                         page={"id": page_data.id, 
                               "document_id": page_data.document_id,
                               "page_index": page_data.page_index,
                               "image_path": page_data.image_path},
                         doc={"id": page_data.document_id, "filename": page_data.filename},
                         annotations=annotations_list,
                         current_emoji=current_emoji,
                         emotion_counts=emotion_counts,
                         prev_page_id=prev_page_id,
                         next_page_id=next_page_id,
                         user=user)

@app.route("/page/<int:page_id>/annotate", methods=["POST"])
@login_required
def annotate(page_id):
    data = request.get_json()
    
    with engine.begin() as conn:
        # Check if page exists
        page = conn.execute(
            text("SELECT id FROM pages WHERE id = :page_id"),
            {"page_id": page_id}
        ).first()
        
        if not page:
            return jsonify({"error": "Page not found"}), 404
            
        user = get_current_user()
        
        # Insert annotation
        result = conn.execute(
            text("""
                INSERT INTO annotations (page_id, user_id, kind, x, y, w, h, text, color, created_at)
                VALUES (:page_id, :user_id, :kind, :x, :y, :w, :h, :text, :color, :created_at)
                RETURNING id, created_at
            """),
            {
                "page_id": page_id,
                "user_id": user['id'],
                "kind": data["kind"],
                "x": data.get("x"),
                "y": data.get("y"),
                "w": data.get("w"),
                "h": data.get("h"),
                "text": data.get("text"),
                "color": data.get("color"),
                "created_at": dt.datetime.utcnow().isoformat()
            }
        )
        
        annotation = result.first()
        
    return jsonify({
        "id": annotation.id,
        "page_id": page_id,
        "kind": data["kind"],
        "x": data.get("x"),
        "y": data.get("y"),
        "w": data.get("w"),
        "h": data.get("h"),
        "text": data.get("text"),
        "color": data.get("color"),
        "created_at": annotation.created_at
    })

@app.route("/static/images/<path:rel>")
def serve_image(rel):
    # Serve generated images from images/ directory
    return send_from_directory(IMAGES_DIR.as_posix(), rel)

@app.route("/staticfile/<path:rel>")
def staticfile(rel):
    # Serve generated images from disk (backward compatibility)
    full = BASE_DIR / rel
    return send_from_directory(full.parent.as_posix(), full.name)

@app.route("/annotations/<int:ann_id>", methods=["DELETE"])
@login_required
def delete_annotation(ann_id):
    user = get_current_user()
    with engine.begin() as conn:
        # Only allow users to delete their own annotations
        result = conn.execute(
            text("DELETE FROM annotations WHERE id = :ann_id AND user_id = :user_id RETURNING id"),
            {"ann_id": ann_id, "user_id": user['id']}
        )
        
        if not result.first():
            return jsonify({"error": "Annotation not found or you don't have permission to delete it"}), 404
            
    return jsonify({"status": "success"})

@app.route("/page/<int:page_id>/reaction", methods=["GET", "POST"])
@login_required
def reaction(page_id):
    with engine.begin() as conn:
        # Check if page exists
        page_row = conn.execute(
            text("SELECT id FROM pages WHERE id = :id"),
            {"id": page_id}
        ).one_or_none()
        
        if not page_row:
            abort(404)
        
        user = get_current_user()
        
        if request.method == "GET":
            # Get existing reaction for this user
            reaction_row = conn.execute(
                text("SELECT emoji FROM reactions WHERE page_id = :pid AND user_id = :user_id"),
                {"pid": page_id, "user_id": user['id']}
            ).one_or_none()
            
            if reaction_row:
                return jsonify({"emoji": reaction_row.emoji})
            return jsonify({"emoji": None})
        
        # POST: Save reaction
        data = request.get_json(silent=True) or {}
        emoji = data.get("emoji")
        
        if emoji is None:
            # Delete reaction if emoji is null
            conn.execute(
                text("DELETE FROM reactions WHERE page_id = :pid AND user_id = :user_id"),
                {"pid": page_id, "user_id": user['id']}
            )
        else:
            # Upsert: one reaction per page per user; replace if it exists
            # First try to update, if no rows affected, insert
            result = conn.execute(
                text("""
                    UPDATE reactions 
                    SET emoji = :emoji, created_at = :ts
                    WHERE page_id = :pid AND user_id = :user_id
                """),
                {
                    "pid": page_id,
                    "user_id": user['id'],
                    "emoji": emoji,
                    "ts": dt.datetime.utcnow().isoformat()
                }
            )
            if result.rowcount == 0:
                # No existing reaction, insert new one
                conn.execute(
                    text("""
                        INSERT INTO reactions (page_id, user_id, emoji, created_at)
                        VALUES (:pid, :user_id, :emoji, :ts)
                    """),
                    {
                        "pid": page_id,
                        "user_id": user['id'],
                        "emoji": emoji,
                        "ts": dt.datetime.utcnow().isoformat()
                    }
                )

    return jsonify({"ok": True})

# --- User Management Routes (Teacher only) ---
@app.route("/users", methods=["GET"])
@teacher_required
def list_users():
    with engine.begin() as conn:
        users = conn.execute(
            text("SELECT id, username, role, created_at FROM users ORDER BY role, username")
        ).all()
    return render_template("users.html", users=users, current_user=get_current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    """Student self-registration"""
    # Only allow registration if user is not logged in
    if 'user_id' in session:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not username or not password:
            return render_template("register.html", error="Username and password required")
        
        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match")
        
        if len(password) < 4:
            return render_template("register.html", error="Password must be at least 4 characters long")
        
        password_hash = hash_password(password)
        
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO users (username, password_hash, role, created_at)
                        VALUES (:username, :password_hash, :role, :created_at)
                    """),
                    {
                        "username": username,
                        "password_hash": password_hash,
                        "role": "student",  # Students can only create student accounts
                        "created_at": dt.datetime.utcnow().isoformat()
                    }
                )
            # Auto-login after registration
            with engine.begin() as conn:
                user = conn.execute(
                    text("SELECT id, username, role FROM users WHERE username = :username"),
                    {"username": username}
                ).first()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for("index"))
        except Exception as e:
            return render_template("register.html", error="Username already exists. Please choose a different username.")
    
    return render_template("register.html")

@app.route("/users/create", methods=["GET", "POST"])
@teacher_required
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        
        if not username or not password:
            return render_template("create_user.html", error="Username and password required", current_user=get_current_user())
        
        if role not in ["teacher", "student"]:
            role = "student"
        
        password_hash = hash_password(password)
        
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO users (username, password_hash, role, created_at)
                        VALUES (:username, :password_hash, :role, :created_at)
                    """),
                    {
                        "username": username,
                        "password_hash": password_hash,
                        "role": role,
                        "created_at": dt.datetime.utcnow().isoformat()
                    }
                )
            return redirect(url_for("list_users"))
        except Exception as e:
            return render_template("create_user.html", error="Username already exists", current_user=get_current_user())
    
    return render_template("create_user.html", current_user=get_current_user())

@app.route("/documents/<doc_id>/assign", methods=["GET", "POST"])
@teacher_required
def assign_document(doc_id):
    user = get_current_user()
    
    # Verify document belongs to this teacher
    with engine.begin() as conn:
        doc = conn.execute(
            text("SELECT id, filename FROM documents WHERE id = :id AND uploaded_by = :user_id"),
            {"id": doc_id, "user_id": user['id']}
        ).first()
        
        if not doc:
            abort(404)
        
        if request.method == "POST":
            student_ids = request.form.getlist("student_ids")
            # Remove existing assignments
            conn.execute(
                text("DELETE FROM document_assignments WHERE document_id = :doc_id"),
                {"doc_id": doc_id}
            )
            # Add new assignments
            for student_id in student_ids:
                try:
                    conn.execute(
                        text("""
                            INSERT INTO document_assignments (document_id, student_id, assigned_at)
                            VALUES (:doc_id, :student_id, :assigned_at)
                        """),
                        {
                            "doc_id": doc_id,
                            "student_id": int(student_id),
                            "assigned_at": dt.datetime.utcnow().isoformat()
                        }
                    )
                except:
                    pass  # Skip duplicates
            
            return redirect(url_for("document", doc_id=doc_id))
        
        # GET: Show assignment form
        students = conn.execute(
            text("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
        ).all()
        
        assigned_students = conn.execute(
            text("""
                SELECT student_id FROM document_assignments WHERE document_id = :doc_id
            """),
            {"doc_id": doc_id}
        ).all()
        assigned_ids = {row.student_id for row in assigned_students}
    
    return render_template("assign_document.html", doc=doc, students=students, assigned_ids=assigned_ids, current_user=user)

@app.route("/documents/<doc_id>/delete", methods=["POST"])
@teacher_required
def delete_document(doc_id):
    """Teacher can delete their own documents"""
    user = get_current_user()
    
    with engine.begin() as conn:
        # Verify document belongs to this teacher
        doc = conn.execute(
            text("SELECT id, filename FROM documents WHERE id=:id AND (uploaded_by=:user_id OR uploaded_by IS NULL)"),
            {"id": doc_id, "user_id": user['id']}
        ).first()
        
        if not doc:
            abort(404)
        
        # Delete all related data
        # First delete annotations (via pages)
        conn.execute(
            text("""
                DELETE FROM annotations 
                WHERE page_id IN (
                    SELECT id FROM pages WHERE document_id = :doc_id
                )
            """),
            {"doc_id": doc_id}
        )
        
        # Delete reactions
        conn.execute(
            text("""
                DELETE FROM reactions 
                WHERE page_id IN (
                    SELECT id FROM pages WHERE document_id = :doc_id
                )
            """),
            {"doc_id": doc_id}
        )
        
        # Delete document assignments
        conn.execute(
            text("DELETE FROM document_assignments WHERE document_id = :doc_id"),
            {"doc_id": doc_id}
        )
        
        # Delete pages
        conn.execute(
            text("DELETE FROM pages WHERE document_id = :doc_id"),
            {"doc_id": doc_id}
        )
        
        # Delete document
        conn.execute(
            text("DELETE FROM documents WHERE id = :doc_id"),
            {"doc_id": doc_id}
        )
    
    return redirect(url_for("index"))

@app.route("/users/<int:user_id>/reset-password", methods=["GET", "POST"])
@teacher_required
def reset_user_password(user_id):
    """Teacher can reset a student's password"""
    current_user = get_current_user()
    
    with engine.begin() as conn:
        # Get the user to reset
        user = conn.execute(
            text("SELECT id, username, role FROM users WHERE id = :user_id"),
            {"user_id": user_id}
        ).first()
        
        if not user:
            abort(404)
        
        # Only allow resetting student passwords (teachers can't reset other teachers' passwords)
        if user.role != 'student':
            abort(403)
        
        if request.method == "POST":
            new_password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            
            if not new_password:
                return render_template("reset_password.html", 
                                     user={"id": user.id, "username": user.username, "role": user.role},
                                     error="Password is required",
                                     current_user=current_user)
            
            if new_password != confirm_password:
                return render_template("reset_password.html",
                                     user={"id": user.id, "username": user.username, "role": user.role},
                                     error="Passwords do not match",
                                     current_user=current_user)
            
            if len(new_password) < 4:
                return render_template("reset_password.html",
                                     user={"id": user.id, "username": user.username, "role": user.role},
                                     error="Password must be at least 4 characters long",
                                     current_user=current_user)
            
            password_hash = hash_password(new_password)
            
            conn.execute(
                text("UPDATE users SET password_hash = :password_hash WHERE id = :user_id"),
                {"password_hash": password_hash, "user_id": user_id}
            )
            
            return redirect(url_for("list_users"))
    
    return render_template("reset_password.html",
                         user={"id": user.id, "username": user.username, "role": user.role},
                         current_user=current_user)
