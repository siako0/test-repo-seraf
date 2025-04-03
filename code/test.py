import yaml
import json
import sys

def convert_grafeas_to_sarif(grafeas_file, sarif_file):
    # Carica il file YAML
    with open(grafeas_file, 'r') as gf:
        grafeas_data = yaml.safe_load(gf)
    
    # Crea la struttura SARIF
    sarif_report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Grafeas Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://grafeas.io/",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }
    
    # Estrarre le regole e i risultati SARIF
    tool_rules = sarif_report["runs"][0]["tool"]["driver"]["rules"]
    results = sarif_report["runs"][0]["results"]
    
    # Itera su ogni occurrence nel file GRAFEAS
    for occurrence in grafeas_data.get("occurrences", []):
        vulnerability = occurrence.get("vulnerability", {})
        note_name = occurrence.get("noteName", "Unknown")
        severity = vulnerability.get("severity", "UNKNOWN").upper()
        package = occurrence.get("resourceUri", "Unknown Package")
        description = vulnerability.get("shortDescription", "No description provided")
        
        # Creazione dell'ID della regola da noteName
        rule_id = note_name.split("/")[-1]
        rule_entry = {
            "id": rule_id,
            "shortDescription": {"text": description},
            "fullDescription": {"text": description},
            "helpUri": f"https://security-tracker.debian.org/tracker/{rule_id}",
            "properties": {"severity": severity}
        }
        
        if rule_entry not in tool_rules:
            tool_rules.append(rule_entry)
        
        # Creazione del risultato SARIF per ogni occurrence
        result_entry = {
            "ruleId": rule_id,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": package
                        }
                    }
                }
            ],
            "severity": severity.lower()
        }
        
        results.append(result_entry)
    
    # Scrive il report SARIF su un file
    with open(sarif_file, 'w') as sf:
        json.dump(sarif_report, sf, indent=4)
    
    print(f"Converted {grafeas_file} to {sarif_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_grafeas_to_sarif.py <grafeas.yaml> <output.sarif>")
        sys.exit(1)
    
    import yaml
    convert_grafeas_to_sarif(sys.argv[1], sys.argv[2])
