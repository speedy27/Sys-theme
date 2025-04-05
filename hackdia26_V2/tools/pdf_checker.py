#pip install PyMuPDF

import fitz  # PyMuPDF
import re
import os

def extract_all_links_from_attachments(filename):
    folder_path = os.path.join(os.path.dirname(__file__), "attachments")
    pdf_path = os.path.join(folder_path, filename)

    if not os.path.exists(pdf_path) or not filename.lower().endswith(".pdf"):
        return False, []

    links = set()
    with fitz.open(pdf_path) as doc:
        for page in doc:
            for link in page.get_links():
                uri = link.get("uri")
                if uri:
                    links.add(uri)

            text_links = re.findall(r'https?://[^\s")>\]]+', page.get_text())
            links.update(text_links)

    return (True, list(links)) if links else (False, [])
