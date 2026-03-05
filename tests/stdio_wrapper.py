import sys
import json
import httpx

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
            
        try:
            req = json.loads(line)
            # Proxy request to HTTP agent for testing
            resp = httpx.post("http://localhost:8000/chat", json=req, timeout=5)
            sys.stdout.write(resp.text + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
