import glob

from django.shortcuts import render, redirect

from .handlers import run_nuclei_scan

NO_RESULT_STRING = "No results found. Happy hacking!"


def nuclei_index(request):
    files = glob.glob("nuclei-templates" + "/**/*.yaml", recursive=True)
    templates = {}

    for f in files:
        template = f.split("/")
        category = str(template[1])

        if category not in templates:
            templates[category] = []

        template_path = "/".join(template)
        templates[category].append(template_path)

    return render(request, "nuclei_index.html", {"templates": templates})


def nuclei_scan(request):
    if request.method == "POST":

        # get paramter from user for domain and selected list of template
        domain = request.POST["domain"]
        list_template = request.POST.getlist("list_template")

        # run nuclei scan via handler

        nuclei_scan_result = run_nuclei_scan(domain, list_template)
        nuclei_output_splitted = nuclei_scan_result.split("\n")

        nuclei_outputs = nuclei_output_splitted[12:]
        nuclei_result = ""
        nuclei_infos = []
        nuclei_findings = []
        nuclei_template_stat = ""

        for nuclei_output in nuclei_outputs:
            nuclei_output_splitted = nuclei_output.split(" ")
            if nuclei_output_splitted[0] == "[INF]":
                nuclei_infos.append(nuclei_output)
            else:
                if nuclei_output:
                    nuclei_findings.append(nuclei_output)

        # if no result found
        if NO_RESULT_STRING.lower() in nuclei_infos[-1].lower():
            nuclei_result = NO_RESULT_STRING
            nuclei_template_stat = nuclei_infos[-2]
        # if result found
        else:
            nuclei_result = "Result Found"
            nuclei_template_stat = nuclei_infos[-1]

        nuclei_infos_as_dict = []

        # info about scanned template
        for nuclei_info in nuclei_infos:
            nuclei_info_splitted = nuclei_info.split(" ")
            nuclei_infos_as_dict.append(
                {
                    "id": nuclei_info_splitted[1],
                    "desc": " ".join(nuclei_info_splitted[2:-2]),
                    "severity": nuclei_info_splitted[-1],
                }
            )

        nuclei_findings_as_dict = []
        # info about finding for mat [tempalte_name:vuln_name]
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

        return render(
            request,
            "nuclei_scan.html",
            {
                "nuclei_template_stat": nuclei_template_stat,
                "nuclei_result": nuclei_result,
                "nuclei_infos_as_dict": nuclei_infos_as_dict,
                "nuclei_findings_as_dict": nuclei_findings_as_dict,
            },
        )
    else:
        return redirect("/")
