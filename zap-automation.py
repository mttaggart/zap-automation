import zapv2
import argparse
from time import sleep
import os

parser = argparse.ArgumentParser(description="Automation for OWASP ZAPROXY")

parser.add_argument("-k",
                    "--api-key",
                    dest="api_key",
                    action="store",
                    required=True,
                    help="OWASP ZAP API Key")

parser.add_argument("-i",
                    "--input-file",
                    dest="input_file",
                    action="store",
                    required=True,
                    help="File of target URLs")

parser.add_argument("-t",
                    "--tech-list",
                    dest="technologies",
                    action="store",
                    required=False,
                    help="Comma-separated list of technologies")

parser.add_argument("-o",
                    "--output-dir",
                    dest="output_dir",
                    action="store",
                    required=False,
                    help="Destination for HTML reports")

def main():
    args = parser.parse_args()
    
    # Load Targets
    with open(args.input_file) as f:
        targets = [l.strip() for l in f.readlines()]
    
    # Initialize Proxy
    zap = zapv2.ZAPv2(apikey=args.api_key)
    zap.core.new_session()
    for t in targets:
        zap.urlopen(t)

        # New Context
        zap.context.new_context(t)
        zap.context.include_in_context(t, t)

        if args.technologies:
            zap.context.exclude_all_context_technologies(t)
            zap.context.include_context_technologies(t, args.technologies)

        # Spider target
        spider_id = zap.spider.scan(t)
        while int(zap.spider.status(spider_id)) < 100:
            print(f"{t}: Spider complete: {zap.spider.status(spider_id)}")
            sleep(3)
        
        print(f"{t}: Spider complete!")
        
        active_id = zap.ascan.scan(t)
        while int(zap.ascan.status(active_id)) < 100:
            print(f"{t}: Active scan complete: {zap.ascan.status(active_id)}")
            sleep(3)

        if args.output_dir:
            path = args.output_dir
            filename = t.replace("https://","")
            if not os.path.isdir(path):
                os.mkdir(path)
            with open(f"{path}/{filename}.html", "w") as f:
                f.write(zap.core.htmlreport())

if __name__ == "__main__":
    main()