from fastapi import APIRouter, Depends, HTTPException, status, Request
import time
import jwt
from app.schemas import TokenExchangeResponse, StandardActionResponse, UserLogin
from app.security import verify_password, create_access_token, create_refresh_token
# YAHAN CHANGE KIYA: oauth2_scheme ki jagah ab security_scheme import kar rahe hain
from app.dependencies import security_scheme

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenExchangeResponse)
async def login(user_data: UserLogin, request: Request):
    db_pool = request.app.state.db_pool
    
    # User fetch karo
    user = await db_pool.fetchrow("SELECT * FROM users WHERE email = $1", user_data.email)
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        
    # Dual Tokens generate karo
    access_token = create_access_token(data={"sub": user["email"]})
    refresh_token = create_refresh_token(data={"sub": user["email"]})
    
    return TokenExchangeResponse(access_token=access_token, refresh_token=refresh_token)

# YAHAN CHANGE KIYA: Logout route ko update kiya taake naye token extraction method ko use kare
@router.post("/logout", response_model=StandardActionResponse)
async def logout(request: Request, creds = Depends(security_scheme)):
    token = creds.credentials
    # Payload extract karo bina verify kiye taake remaining life mil sake
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp", 0)
        ttl = exp - int(time.time())
        
        # Agar token abhi expire nahi hua toh Redis me uski remaining life ke hisaab se blacklist kar do
        if ttl > 0:
            redis_client = request.app.state.redis_client
            await redis_client.setex(f"blacklist:{token}", ttl, "true")
    except Exception:
        pass 
        
    return StandardActionResponse(detail="Revocation complete")