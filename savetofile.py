import json
def save_summary_and_findings_to_file(summary, findings, filename="output.txt"):
    """
    Saves the given summary and findings to a file.
    :param summary: The summary text to be saved.
    :param findings: The findings to be saved.
    :param filename: The name of the file where the summary and findings will be saved.
    """
    with open(filename, "w") as file:
        file.write("Summary:\n")
        file.write(summary)
        file.write("\n\nFindings:\n")
        for finding in findings:
            file.write(json.dumps(finding) + "\n")
