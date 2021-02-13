import io
import subprocess
import datetime
import urllib
import base64

NO_RESULT_STRING = "No results found. Happy hacking!"


def run_nuclei_scan(domain, list_template):
    datetime_now = datetime.datetime.now()
    _ = datetime_now.strftime("%Y-%m-%d %H:%M:%S")

    template_params = [v for template in list_template for v in ("-t", template)]

    run_nuclei_commands = (
        ["nuclei", "-target", domain] + template_params + ["-no-color"]
    )

    process = subprocess.Popen(
        run_nuclei_commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    nuclei_stdout = process.stdout.read().decode("utf-8")
    nuclei_stderr = process.stderr.read().decode("utf-8")

    result = nuclei_stderr + nuclei_stdout

    # formatting output
    nuclei_output_splitted = result.split("\n")

    nuclei_outputs = nuclei_output_splitted[12:]
    nuclei_result = ""
    nuclei_infos = []
    nuclei_findings = []
    nuclei_template_stat = ""

    # seperate [INF] section with finding section
    for nuclei_output in nuclei_outputs:
        nuclei_output_splitted = nuclei_output.split(" ")
        if nuclei_output_splitted[0] == "[INF]":
            nuclei_infos.append(nuclei_output)
        else:
            if nuclei_output:
                nuclei_findings.append(nuclei_output)

    # if no result found after running nuclei scan
    if NO_RESULT_STRING.lower() in nuclei_infos[-1].lower():
        nuclei_result = NO_RESULT_STRING
        nuclei_template_stat = nuclei_infos[-2]
        nuclei_infos = nuclei_infos[:-2]

    # if result found after running nuclei scan
    else:
        nuclei_result = "Result Found"
        nuclei_template_stat = nuclei_infos[-1]
        nuclei_infos = nuclei_infos[:-1]

    # create list of dict contain template used information
    nuclei_infos_as_dict = []
    for nuclei_info in nuclei_infos:
        nuclei_info_splitted = nuclei_info.split(" ")
        nuclei_infos_as_dict.append(
            {
                "id": nuclei_info_splitted[1],
                "desc": " ".join(nuclei_info_splitted[2:-2]),
                "severity": nuclei_info_splitted[-1],
            }
        )

    # create list of dict contain finding information
    nuclei_findings_as_dict = []
    for nuclei_finding in nuclei_findings:
        nuclei_finding_splitted = nuclei_finding.split(" ")
        template_subtemplate = nuclei_finding_splitted[0]
        finding_splitted = template_subtemplate.split(":")
        nuclei_findings_as_dict.append(
            {
                "template": finding_splitted[0].replace("[", ""),
                "sub_template": finding_splitted[1].replace("]", ""),
                "protocol": nuclei_finding_splitted[1],
                "severity": nuclei_finding_splitted[2],
                "path": nuclei_finding_splitted[2],
            }
        )

    # get pie chart for each section

    # pie chart for template used
    severity_template_counter = {}
    for nuclei_info_as_dict in nuclei_infos_as_dict:
        if nuclei_info_as_dict["severity"] not in severity_template_counter:
            severity_template_counter[nuclei_info_as_dict["severity"]] = 0
        severity_template_counter[nuclei_info_as_dict["severity"]] += 1

    total_template = len(nuclei_infos_as_dict)

    template_labels = []
    template_y = []

    for severity, counter in severity_template_counter.items():
        template_labels.append(severity)
        template_y.append(counter)

    template_used_data = [template_labels, template_y]

    print(template_used_data)

    return (
        nuclei_template_stat,
        nuclei_result,
        nuclei_infos_as_dict,
        nuclei_findings_as_dict,
        template_used_data,
    )
