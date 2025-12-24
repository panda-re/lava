from lava import parse_lava_args

# from .taint import TaintManager  # Future consolidation
# from .inject import InjectionManager # Future consolidation

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