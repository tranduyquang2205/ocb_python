from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from ocb import OCB,loginOCB,sync_balance_ocb,sync_ocb



app = FastAPI()
@app.get("/")
def read_root():
    return {"Hello": "World"}
class LoginDetails(BaseModel):
    username: str
    password: str
    account_number: str
    proxy_list: list
    
@app.post('/login', tags=["login"])
def login_api(input: LoginDetails):
        ocb = OCB(input.username, input.password, input.account_number,input.proxy_list)
        result = loginOCB(ocb)
        return (result)

@app.post('/get_balance', tags=["get_balance"])
def get_balance_api(input: LoginDetails):
        ocb = OCB(input.username, input.password, input.account_number,input.proxy_list)
        balance = sync_balance_ocb(ocb)
        return (balance)
    
class Transactions(BaseModel):
    username: str
    password: str
    account_number: str
    from_date: str
    to_date: str
    limit: int
    proxy_list: list
    
@app.post('/get_transactions', tags=["get_transactions"])
def get_transactions_api(input: Transactions):
        ocb = OCB(input.username, input.password, input.account_number,input.proxy_list)
        loginOCB(ocb)
        transactions = sync_ocb(ocb,input.from_date,input.to_date,input.limit)
        return (transactions)
    
if __name__ == "__main__":
    uvicorn.run(app ,host='0.0.0.0', port=3000)