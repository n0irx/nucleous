import glob

from django.shortcuts import render, redirect

from .handlers import run_nuclei_scan


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
        (
            nuclei_template_stat,
            nuclei_result,
            nuclei_infos_as_dict,
            nuclei_findings_as_dict,
            template_used_data,
        ) = run_nuclei_scan(domain, list_template)

        return render(
            request,
            "nuclei_scan.html",
            {
                "nuclei_template_stat": nuclei_template_stat,
                "nuclei_result": nuclei_result,
                "nuclei_infos_as_dict": nuclei_infos_as_dict,
                "nuclei_findings_as_dict": nuclei_findings_as_dict,
                "template_used_data": template_used_data,
            },
        )
    else:
        return redirect("/")
