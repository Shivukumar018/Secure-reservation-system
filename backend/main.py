from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import create_engine, Column, Integer, String, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from passlib.context import CryptContext
from passlib.exc import UnknownHashError

import random
from datetime import datetime
import os

# Import secrets/config from security.state (must exist in env)
from security.state import INTERNAL_SECRET as INTERNAL_SECRET_FROM_STATE, SESSION_SECRET

# ========================
#   App Setup
# ========================
app = FastAPI(title="Golden Express Reservation")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET environment variable is required for SessionMiddleware.")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# >>> INTERNAL SECRET PROTECTION <<<
INTERNAL_SECRET = INTERNAL_SECRET_FROM_STATE

@app.middleware("http")
async def require_internal_secret(request: Request, call_next):
    # Allow health-check endpoint for probes
    if request.url.path == "/health":
        return await call_next(request)

    provided = (request.headers.get("x-internal-secret") or "").strip()
    expected = (INTERNAL_SECRET or "").strip()

    if provided != expected:
        raise HTTPException(status_code=403, detail="Direct access blocked")

    return await call_next(request)
# >>> END SECRET CHECK <<<

# --- Fix: use absolute paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "frontend"))

app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(FRONTEND_DIR, "templates"))

# ========================
#   Database Setup
# ========================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# ========================
#   Password Hashing
# ========================
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ========================
#   Models
# ========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    phone = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String)
    trainno = Column(String)
    train_name = Column(String)
    from_city = Column(String)
    to_city = Column(String)
    class_type = Column(String)
    passengers = Column(Integer)
    amount = Column(String)
    booking_time = Column(String)
    invoice_no = Column(String)

Base.metadata.create_all(bind=engine)

# ========================
#   Helper Functions
# ========================
CITIES = [
    "Bengaluru", "Mysuru", "Hubballi", "Mangaluru", "Chennai", "Hyderabad", "Mumbai", "Delhi",
    "Pune", "Ahmedabad", "Kolkata", "Jaipur", "Coimbatore", "Madurai", "Lucknow", "Patna",
    "Erode", "Vijayawada", "Thiruvananthapuram", "Bhopal", "Indore", "Chandigarh", "Noida", "Gurugram"
]

def get_username(request: Request) -> Optional[str]:
    user_email = request.session.get("user")
    if not user_email:
        return None
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == user_email).first()
        return user.name if user else None
    finally:
        db.close()

def render(template: str, request: Request, **kwargs):
    ctx = {"request": request, "msg": request.query_params.get("msg"), "username": get_username(request)}
    ctx.update(kwargs)
    return templates.TemplateResponse(template, ctx)

def mock_availability(frm, to):
    frm, to = (frm or "").strip(), (to or "").strip()
    if not frm or not to or frm == to:
        return []
    trains = [
        {"no": "12001", "name": "Shatabdi Express"},
        {"no": "12223", "name": "Duronto Express"},
        {"no": "12627", "name": "Karnataka Express"},
        {"no": "12951", "name": "Rajdhani Express"},
        {"no": "12430", "name": "Bangalore Mail"},
        {"no": "16382", "name": "Canara Express"},
        {"no": "12863", "name": "Humsafar Express"},
    ]
    if random.random() < 0.3:
        return []
    picked = random.sample(trains, k=min(random.randint(2, 3), len(trains)))
    result = []
    for t in picked:
        dep_h, dep_m = random.randint(1, 12), random.randint(0, 59)
        arr_h, arr_m = random.randint(1, 12), random.randint(0, 59)
        result.append({
            "no": t["no"], "name": t["name"], "frm": frm, "to": to,
            "dep": f"{dep_h}:{dep_m:02d} {'AM' if random.choice([True, False]) else 'PM'}",
            "arr": f"{arr_h}:{arr_m:02d} {'AM' if random.choice([True, False]) else 'PM'}",
            "seats": random.randint(10, 120)
        })
    return result

# ========================
#   Routes
# ========================
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/dashboard")
    return render("index.html", request)

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render("register.html", request)

@app.post("/register")
def register_user(
    name: str = Form(...),
    phone: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return HTMLResponse("PasswordMismatch")

    db: Session = SessionLocal()
    try:
        exists = db.query(User).filter(or_(User.email == email, User.phone == phone)).first()
        if exists:
            return HTMLResponse("UserExists")

        # bcrypt fix: truncate long passwords
        password = password[:72]
        hashed = pwd_ctx.hash(password)

        db.add(User(name=name, phone=phone, email=email, password=hashed))
        db.commit()
        return HTMLResponse("RegistrationSuccess")
    finally:
        db.close()

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render("login.html", request)

# --- Fixed Login Handler (handles UnknownHashError cleanly) ---
@app.post("/login")
def login_user(request: Request, identifier: str = Form(...), password: str = Form(...)):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(or_(User.email == identifier, User.phone == identifier)).first()
        if not user:
            return Response("UserNotFound", status_code=404, media_type="text/plain")

        try:
            verified = pwd_ctx.verify(password, user.password)
        except UnknownHashError:
            # Stored password not hashed properly (e.g., plaintext in DB)
            verified = False
        except Exception:
            verified = False

        if not verified:
            return Response("InvalidCredentials", status_code=401, media_type="text/plain")

        request.session["user"] = user.email
        return RedirectResponse("/dashboard", status_code=302)
    finally:
        db.close()

@app.get("/logout")
def logout_user(request: Request):
    request.session.clear()
    return RedirectResponse("/logout_success")

@app.get("/logout_success", response_class=HTMLResponse)
def logout_success(request: Request):
    return render("logout_success.html", request)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login?msg=Please+login+first")
    return render("dashboard.html", request, cities=CITIES)

@app.get("/search", response_class=HTMLResponse)
def search_guest(request: Request, frm: str = "", to: str = ""):
    results = mock_availability(frm, to) if (frm and to) else None
    return render("search_guest.html", request, frm=frm, to=to, results=results, cities=CITIES)

@app.get("/search/auth", response_class=HTMLResponse)
def search_auth(request: Request, frm: str = "", to: str = ""):
    if not request.session.get("user"):
        return RedirectResponse("/search?msg=Login+to+book")
    results = mock_availability(frm, to) if (frm and to) else None
    return render("search_auth.html", request, frm=frm, to=to, results=results, cities=CITIES)

@app.get("/book", response_class=HTMLResponse)
def book_page(request: Request, trainno: str = "", name: str = "", from_: str = "", to: str = ""):
    if not request.session.get("user"):
        return RedirectResponse("/login?msg=Please+login+first")
    return render("book.html", request, trainno=trainno, name=name, from_=from_, to=to)

@app.post("/payment", response_class=HTMLResponse)
def payment_page(
    request: Request,
    trainno: str = Form(...),
    name: str = Form(...),
    from_: str = Form(...),
    to: str = Form(...),
    cls: str = Form(...),
    passengers: int = Form(...),
    amount: str = Form(...),
):
    if not request.session.get("user"):
        return RedirectResponse("/login?msg=Please+login+first")
    request.session["payment_data"] = {
        "trainno": trainno,
        "name": name,
        "from_": from_,
        "to": to,
        "cls": cls,
        "passengers": passengers,
        "amount": amount,
    }
    return render("payment.html", request, **request.session["payment_data"])

@app.get("/invoice", response_class=HTMLResponse)
def invoice_page(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login?msg=Please+login+first")
    
    user_email = request.session.get("user")
    payment_data = request.session.get("payment_data")

    db: Session = SessionLocal()
    try:
        if payment_data:
            existing = db.query(Booking).filter(
                Booking.user_email == user_email,
                Booking.trainno == payment_data["trainno"],
                Booking.train_name == payment_data["name"]
            ).first()
            if existing:
                booking = existing
            else:
                booking_time = datetime.now().strftime("%d %b %Y, %I:%M %p")
                invoice_no = f"INV{random.randint(100000, 999999)}"
                booking = Booking(
                    user_email=user_email,
                    trainno=payment_data["trainno"],
                    train_name=payment_data["name"],
                    from_city=payment_data["from_"],
                    to_city=payment_data["to"],
                    class_type=payment_data["cls"],
                    passengers=payment_data["passengers"],
                    amount=payment_data["amount"],
                    booking_time=booking_time,
                    invoice_no=invoice_no
                )
                db.add(booking)
                db.commit()
            request.session.pop("payment_data", None)
            return render("invoice.html", request, booking=booking)

        booking = db.query(Booking).filter(Booking.user_email == user_email).order_by(Booking.id.desc()).first()
        if not booking:
            return RedirectResponse("/dashboard?msg=No+Payment+Record+Found")
        return render("invoice.html", request, booking=booking)
    finally:
        db.close()

@app.get("/bookings", response_class=HTMLResponse)
def bookings_page(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login?msg=Please+login+first")
    db: Session = SessionLocal()
    try:
        bookings = db.query(Booking).filter(Booking.user_email == request.session["user"]).all()
        return render("bookings.html", request, bookings=bookings)
    finally:
        db.close()

# ========================
#   Run the app
# ========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("BACKEND_PORT", "5000")))
