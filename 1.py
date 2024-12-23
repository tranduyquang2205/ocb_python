import requests
import json

url = "https://ocbomni.ocb.com.vn/api/access-control/client-api/v3/accessgroups/user-context"

payload = json.dumps({
  "serviceAgreementId": "8aaad4f8904effa5019055b2c8cf5551"
})
headers = {
  'Accept': 'application/json',
  'Accept-Language': 'vi',
  'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWeDNoZ1NFZ0w1SWpQY2UyNURjaEtQM01kNkdadERWVkk5alFnbG5MbnE0In0.eyJleHAiOjE3MzQ5NDg1MzksImlhdCI6MTczNDk0NzYzOSwiYXV0aF90aW1lIjoxNzM0OTQ3NDA5LCJqdGkiOiI4ZmYyNzRhYS1kMWI5LTRlMTMtYmM1MC1jNGIyZDAwMmRiYjIiLCJpc3MiOiJodHRwczovL2lkZW50aXR5LW9tbmkub2NiLmNvbS52bi9hdXRoL3JlYWxtcy9iYWNrYmFzZSIsInN1YiI6ImJkNDVjNGYyLTY2MmEtNGM4NS05MzdkLTBhYzkwYjFmNzFiZSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImJiLXdlYi1jbGllbnQiLCJub25jZSI6IkNDNzJBN0M4LTk4RTUtMTg4RS0xNjEyLTYxMjM0NTk4ODZDMTE2MyIsInNlc3Npb25fc3RhdGUiOiI3NTI3MmU4Yi1hNTk2LTQxZTUtOWRhMy1lNzMzZGMyMGJjMmQiLCJhY3IiOiIxIiwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsInNpZCI6Ijc1MjcyZThiLWE1OTYtNDFlNS05ZGEzLWU3MzNkYzIwYmMyZCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwidXNlcl9uYW1lIjoieWdhODA3MiIsIm1vYmlsZU51bWJlciI6IjA4ODY0Mzg3OTUiLCJuYW1lIjoiVFJBTiBEVVkgUVVBTkciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ5Z2E4MDcyIiwiZ2l2ZW5fbmFtZSI6IlRSQU4gRFVZIiwibG9jYWxlIjoidmkiLCJmYW1pbHlfbmFtZSI6IlFVQU5HIiwiZW1haWwiOiJraG9uZ2RhbmdreUBvY2IuY29tLnZuIiwiaW50ZXJuYWxfc2NvcGUiOlsiYmI6Y2hhbmdlX293bl91c2VybmFtZSIsImNoYW5nZV9vd25fdXNlcm5hbWUiLCJiYjp1c2VybmFtZSIsImJiOnN0ZXAtdXAiLCJiYjpjYXJkc192aWV3X2N2dl9wYW4iLCJzdGVwLXVwIiwidXNlcm5hbWUiLCJjaGFuZ2VfdXNlcm5hbWUiXSwiYXV0aG9yaXRpZXMiOlsiZGVmYXVsdC1yb2xlcy1iYWNrYmFzZSIsInBhc3N3b3JkIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfQ.mDdGDP53VlhHvyPZ1ymHrlwnpiJSNygZwUiZZbgVvMxZWjnCIezUDxPCxL3eLSG_m8YqMOxKvqr8OwcTd1itLR-ZIimvxl5rf70vgtPhK3FR3wbdonRD54mVPAfyyzui0cUvy_1dg64D-RdBI-FHjDA1Ggdn7YOmyXN-0gpQiEYMSKKoAEK3Khfa5PjEle0x5oCwfCvtPB6NU6Yq0_shdo1i2bfKcLt-uGdwwlnAW6tWDvZJlP_bTasitEQg1uPqck_JZDAy7hcStJrAPsTlBHQz9II5IZUdyMYPojZWNR0kE2EA_pBtaxgxRyQj6c98PEJWv6KC2Nuu8GlSv963hQ',
  'Connection': 'keep-alive',
  'Content-Type': 'application/json',
  'Lang': 'vi',
  'Origin': 'https://ocbomni.ocb.com.vn',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  'X-Geo': '',
  'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response,response.text)
