from dotenv import load_dotenv
import argparse
import sys


load_dotenv()


def parse_lava_args():
    parser = argparse.ArgumentParser(
        description="LAVA: Large-scale Automated Vulnerability Addition",
        usage="%(prog)s [options] [ProjectConfig]",
        add_help=False
    )

    # --- Common Options ---
    common = parser.add_argument_group("Common Options")
    common.add_argument("-h", "--help", action="store_true")
    common.add_argument("-a", "--all", action="store_true", help="Run all lava steps")
    common.add_argument("-k", "--force", action="store_true", help="Delete old data without confirmation")
    common.add_argument("-n", "--count", type=int, default=50, help="Number of bugs to inject at once")
    common.add_argument("-y", "--bug-types", default="ptr_add,rel_write,malloc_off_by_one",
                        help="Comma separated list of bug types")
    common.add_argument("-b", "--atp-type", choices=["mem_read", "fn_arg", "mem_write"],
                        help="Specify a single ATP type")

    # --- Step Flags ---
    steps = parser.add_argument_group("Specify Steps to Run")
    steps.add_argument("-r", "--reset", action="store_true", help="Run reset step")
    steps.add_argument("-c", "--clean", action="store_true", help="Run clean step (DB only)")
    steps.add_argument("-q", "--add-queries", action="store_true", help="Run add queries step")
    steps.add_argument("-m", "--make", action="store_true", help="Run make step")
    steps.add_argument("-t", "--taint", action="store_true", help="Run taint step")
    steps.add_argument("-i", "--inject", type=int, metavar="NUM_TRIALS",
                       help="Run inject step with specified number of trials")

    # --- Expert/Dev Options ---
    expert = parser.add_argument_group("Expert only options")
    expert.add_argument("--demo", action="store_true", help="Run lava demo")
    expert.add_argument("--test-data-flow", action="store_true", help="Inject data-flow only, 0 bugs")
    expert.add_argument("--curtail", type=int, default=0, help="Curtail bug-finding after count bugs")
    expert.add_argument("--enable-knob-trigger", help="Enable knob trigger")

    # --- Backwards Compatibility / Combined Flags ---
    # Argparse doesn't natively do '-ak', so we check sys.argv for it later
    # or define it as a hidden action.
    expert.add_argument("-ak", action="store_true", help=argparse.SUPPRESS)

    # --- Positional ---
    parser.add_argument("project_name", nargs='?', help="Name of the project or path to JSON")

    # If no args, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Handle the help flag manually to match your exit behavior
    if args.help:
        parser.print_help()
        sys.exit(0)

    # --- Custom Logic Mapping (Replacing the 'case' logic in Bash) ---

    # Handle -ak and --all shortcuts
    if args.ak or args.all:
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3 if args.inject is None else args.inject
        if args.ak:
            args.force = True

    # Handle positional project_name shorthand (lava.sh ProjectName)
    # Your bash script allowed: lava.sh myproject (with no flags)
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3
        args.project_name = sys.argv[1]

    # Handle --test-data-flow logic
    if args.test_data_flow:
        args.inject = 1
        args.count = 0

    return args


def main():
    # 1. Parse arguments using the logic we refactored
    args = parse_lava_args()

    # 2. Handle the "Can of Worms": Remote/Docker logic
    # Since you're sticking to local CI/CD for now, we just verify
    if args.force:
        print(f"DEBUG: Force flag detected. Proceeding with deletions...")

    # 3. Step Dispatcher
    # This replaces the 'if [ $add_queries -eq 1 ]' blocks in lava.sh

    if args.reset:
        print(">>> Starting Reset Step")
        # For now, put reset logic here or in a small helper in queries.py
        # Porting 'deldir' and 'RESET_DB' logic

    if args.add_queries:
        print(">>> Starting Add Queries Step")
        # We pass the 'args' object directly so QueryManager
        # has everything (atp_type, project_name, etc.)
        # qm = QueryManager(args)
        # qm.step_add_queries()

    if args.taint:
        print(">>> Starting Taint Step (PANDA)")
        # This will eventually call your refactored bug_mining.py

    if args.inject:
        print(f">>> Starting Injection Step ({args.inject} trials)")
        # Loop trials as seen in lava.sh
        for i in range(1, args.inject + 1):
            print(f"--- Trial {i} ---")
            # Call your refactored inject.py logic

    print(">>> All requested LAVA steps finished.")


if __name__ == "__main__":
    main()
