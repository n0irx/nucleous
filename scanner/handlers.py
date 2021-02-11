import subprocess
import datetime


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

    return result
