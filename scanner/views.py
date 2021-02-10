from django.shortcuts import render

import os
import glob

from pathlib import Path
from .handlers import run_nuclei_scan

# Create your views here.
def index(request):

    result = list(Path("nuclei-templates").rglob("*.yaml"))
    files = glob.glob("nuclei-templates" + "/**/*.yaml", recursive=True)
    templates = {}

    for f in files:
        template = f.split("/")
        category = str(template[1])

        if category not in templates:
            templates[category] = []

        template_path = "/".join(template)
        templates[category].append(template_path)

    return render(request, "index.html", {"templates": templates})


def scan(request):
    if request.method == "POST":
        domain = request.POST["domain"]
        list_template = request.POST.getlist("list_template")

        scan_result = run_nuclei_scan(domain, list_template)
        scan_result_splitted = scan_result.split("\n")
        scanned_templates = scan_result_splitted[12:-1]

        scanned_template_results = [
            scan_template.split(" ") for scan_template in scanned_templates
        ]

        scanned_template_stats = scan_result_splitted[-3]
        scanned_template_summary = scan_result_splitted[-2]

        return render(
            request,
            "scan_result.html",
            {
                "scanned_template_results": scanned_template_results,
                "scanned_template_stats": scanned_template_stats,
                "scanned_template_summary": scanned_template_summary
            }
        )
    else:
        return redirect("/scanner")
