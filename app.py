import streamlit as st
import requests
import socket
import pandas as pd

AWS_HINTS = ["amazonaws.com", "cloudfront.net", "awsstatic"]

def check_domain(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=6)
        html = r.text.lower()

        for hint in AWS_HINTS:
            if hint in html:
                return True, hint

        ip = socket.gethostbyname(domain)
        if ip.startswith(("3.", "13.", "18.", "52.", "54.")):
            return True, "AWS IP range"

        return False, ""
    except:
        return False, "error"


st.title("AWS Usage Checker")

file = st.file_uploader("Upload domain CSV", type=["csv"])

if file:
    df = pd.read_csv(file, header=None, names=["domain"])
    results = []

    for d in df["domain"]:
        flag, reason = check_domain(d)
        results.append({
            "domain": d,
            "aws_signal": flag,
            "reason": reason
        })

    out = pd.DataFrame(results)
    st.dataframe(out)

    st.download_button(
        "Download Results",
        out.to_csv(index=False),
        "aws_results.csv"
    )

