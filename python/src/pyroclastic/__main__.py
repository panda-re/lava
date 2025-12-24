import sys
from .lava import lava_main


def main():
    # This just hands the reins over to your main logic file
    sys.exit(lava_main())


if __name__ == "__main__":
    main()
