import requests, json
'''
    XDR API TEST !
'''

XDR_API_SERVER_IP = "192.168.1.205"
XDR_API_SERVER_PORT = 39923

# [POST]
URL__Analysis_TimestampRange = "/api/solution/xdr/analysis/timestamp_range"
URL__Analysis_Anchor         = "/api/solution/xdr/analysis/anchor"

"""print(
  requests.post(
    f"http://{XDR_API_SERVER_IP}:{XDR_API_SERVER_PORT}{URL__Analysis_TimestampRange}",
    json={
      "timestamp":{
        "iso8601":{
          "start": "2025-11-19T23:30:07.614029564Z"
        }
      },
      "size" : 1000
    }
  ).content
)"""

"""print(
  requests.post(
    f"http://{XDR_API_SERVER_IP}:{XDR_API_SERVER_PORT}{URL__Analysis_Anchor}",
    json={
      "root_session_id":"8eff1883a42f58174320a4cd1ad90c06bdddfd83e72bd9bf9c798df025a59c0e",
      "platform": "edr",
      "size" : 1000
    }
  ).content
)"""

with open("test.json", "wb") as f:
  f.write(
    requests.post(
    f"http://{XDR_API_SERVER_IP}:{XDR_API_SERVER_PORT}{URL__Analysis_Anchor}",
    json={
      "root_session_id":"572b67e62ee48d228e1af87740301750b5528db4a0fe95f57266fc5ea7370200",
      "platform": "edr",
      "size" : 1000
    }
  ).content
  )