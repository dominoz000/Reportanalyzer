import re
import spacy
from collections import defaultdict

# Load pre-trained NLP model (e.g., SpaCy or transformers)
nlp = spacy.load("en_core_web_sm")

# Define function to extract IoCs
def extract_iocs(text):
    iocs = defaultdict(list)
    
    # IP address extraction using regex
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    iocs['IP addresses'] = re.findall(ip_pattern, text)
    
    # Domain extraction using regex
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b"
    iocs['Domains'] = re.findall(domain_pattern, text)
    
    # Email extraction using regex
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    iocs['Emails'] = re.findall(email_pattern, text)
    
    return iocs

# Define function to extract TTPs
def extract_ttps(text):
    tactics = []
    techniques = []
    
    # Example Tactics from MITRE ATT&CK (expand this list)
    tactics_mapping = {
        "Initial Access": "TA0001",
        "Execution": "TA0002",
        "Lateral Movement": "TA0008"
    }
    techniques_mapping = {
        "Spear Phishing": "T1566.001",
        "PowerShell": "T1059.001"
    }
    
    # Match tactics and techniques based on keywords
    for tactic, code in tactics_mapping.items():
        if tactic.lower() in text.lower():
            tactics.append([code, tactic])
    
    for technique, code in techniques_mapping.items():
        if technique.lower() in text.lower():
            techniques.append([code, technique])
    
    return {"Tactics": tactics, "Techniques": techniques}

# Define function to extract threat actors
def extract_threat_actors(text):
    threat_actors = []
    # Look for known threat actor names (expand this list)
    known_actors = ["APT33", "Lazarus", "Fancy Bear"]
    for actor in known_actors:
        if actor.lower() in text.lower():
            threat_actors.append(actor)
    return threat_actors

# Define function to extract malware details
def extract_malware(text):
    malware_details = []
    # Look for known malware names (expand this list)
    known_malware = ["Shamoon"]
    for malware in known_malware:
        if malware.lower() in text.lower():
            malware_details.append({'Name': malware, 'md5': 'sample_md5_hash'})
    return malware_details

# Define function to extract targeted entities
def extract_targeted_entities(text):
    targeted_entities = []
    # Example sectors (expand this list)
    known_sectors = ["Energy Sector", "Healthcare", "Finance"]
    for sector in known_sectors:
        if sector.lower() in text.lower():
            targeted_entities.append(sector)
    return targeted_entities

# Main pipeline function
def extract_threat_intelligence(report_text):
    result = {}
    
    # Extract IoCs
    result['IoCs'] = extract_iocs(report_text)
    
    # Extract TTPs
    result['TTPs'] = extract_ttps(report_text)
    
    # Extract Threat Actors
    result['Threat Actor(s)'] = extract_threat_actors(report_text)
    
    # Extract Malware details
    result['Malware'] = extract_malware(report_text)
    
    # Extract Targeted Entities
    result['Targeted Entities'] = extract_targeted_entities(report_text)
    
    return result

# Example report text

import PyPDF2
import pytesseract
from pdf2image import convert_from_path
from PIL import Image
import io

def extract_text_from_pdf(pdf_path):
    try:
        # Open the PDF file in read-binary mode
        with open(pdf_path, 'rb') as pdf_file:
            # Create a PDF reader object
            reader = PyPDF2.PdfReader(pdf_file)
            
            # Initialize a string to store the extracted text
            extracted_text = ""

            # Extract text from each page
            for page_num, page in enumerate(reader.pages):
                # Extract text from the page
                text = page.extract_text()
                if text:
                    extracted_text += f"Text from page {page_num + 1}:\n{text}\n"
                
                # If no text is found, we will extract text from images using OCR
                else:
                    extracted_text += f"Text from images on page {page_num + 1}:\n"
                    # Convert PDF page to image
                    images = convert_from_path(pdf_path, first_page=page_num+1, last_page=page_num+1)
                    for image in images:
                        # Use pytesseract to extract text from image
                        ocr_text = pytesseract.image_to_string(image)
                        extracted_text += ocr_text + "\n"

        return extracted_text

    except Exception as e:
        return f"An error occurred: {e}"

# Example usage
pdf_path = input("please enter the path of your pdf_file : ---   ")  # Replace with your PDF file path
report_text = extract_text_from_pdf(pdf_path)


# Run the pipeline
result = extract_threat_intelligence(report_text)
print(result)