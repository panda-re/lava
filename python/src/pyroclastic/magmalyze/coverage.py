import argparse
from .deploy import GenerationManager


def main():
    parser = argparse.ArgumentParser(description="Calculate code coverage using GCC/LCOV.")
    parser.add_argument("--project", "-p", required=True, dest="project_name",
                        help="Provide the LAVA project name")
    args = parser.parse_args()

    coverage_class = GenerationManager(args)
    coverage_percentage = coverage_class.get_coverage()

    if coverage_percentage >= 0:
        print(f"\nFinal calculated coverage: {coverage_percentage:.2f}%")
    else:
        print("\nCoverage calculation failed.")


if __name__ == '__main__':
    main()