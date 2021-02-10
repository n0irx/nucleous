import os
import subprocess
import sys
import datetime


def run_nuclei_scan(domain, list_template):
    datetime_now = datetime.datetime.now()
    scan_date = datetime_now.strftime("%Y-%m-%d %H:%M:%S")
    template_params = [v for template in list_template for v in ("-t", template)]
    run_nuclei_commands = (
        ["nuclei", "-target", domain] + template_params + ["-no-color"]
    )
    process = subprocess.Popen(
        run_nuclei_commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    result = process.stdout.read().decode("utf-8") + process.stderr.read().decode(
        "utf-8"
    )
    return result
