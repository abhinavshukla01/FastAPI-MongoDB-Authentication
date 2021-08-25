from fastapi import FastAPI
import routes
app = FastAPI()

app.include_router(routes.router)

@app.get("/hello")
def HelloWorld():
    return {"msg": "Hello World"}