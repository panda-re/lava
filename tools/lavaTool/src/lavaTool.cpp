// This makes sure assertions actually occur.
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "lava.hxx"
#include "lexpr.hxx"
#include "lavaTool.h"
#include "MatchFinder.h"
#include <cstdlib>

void parse_whitelist(std::string whitelist_filename) {
    debug(FNARG) <<  "parsing white list " << whitelist_filename << "\n";
    FILE *fp = fopen(whitelist_filename.c_str(), "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        char *p = line;
        char *np = strtok(p, " ");
        char *npp = strtok(NULL, "\n");

        if (npp == NULL) {
            errs() << "Error parsing whitelist file. Ignoring\n";
            continue;
        }

        debug(FNARG) << "\t np= " << np << " npp=" << npp << "\n";
        auto wlp = std::make_pair(std::string(np), std::string(npp));
        whitelist.insert(std::string(npp));
        debug(FNARG) << "white list entry: file = [" << np << "] func = [" << npp << "]\n";

    }
    debug(FNARG) << "whitelist is " << whitelist.size() << " entries\n";
}

int main(int argc, const char **argv) {
    cl::SetVersionPrinter(printVersion);
    CommonOptionsParser op(argc, argv, LavaCategory);

    std::cout << "Starting lavaTool...\n";
    LavaPath = std::string(dirname(dirname(dirname(realpath(argv[0], NULL)))));
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    RANDOM_SEED = ArgRandSeed;
    srand(RANDOM_SEED);


    if (LavaWL != "XXX")
        parse_whitelist(LavaWL);
    else
        debug(FNARG) << "No whitelist\n";

    if (ArgDebug) {
        errs() << "DEBUG MODE: Only adding data_flow\n";

        LavaMatchFinder Matcher;
        Tool.run(newFrontendActionFactory(&Matcher, &Matcher).get());
        return 0;
    }

    if (LavaDB != "XXX") StringIDs = LoadDB(LavaDB);

    odb::transaction *t = nullptr;

    if (LavaAction == LavaInjectBugs) {
        if (DBName == "XXX") {
            errs() << "Error: Specify a database name with \"--db [name]\".  Exiting . . .\n";
            exit(1);
        }
        const char* pgpass = std::getenv("PGPASS");
        const char* pguser = std::getenv("PGUSER");
        if (pgpass) {
            // PGPASS environment variable is set, and pgpass points to its value.
            std::cout << "PGPASS IS SET" << std::endl;
        } else {
            // PGPASS environment variable is not set.
            std::cout << "PGPASS is not set" << std::endl;
            exit(1);
        }

        if (pguser) {
            // PGUSER environment variable is set, and pgpass points to its value.
            std::cout << "PGUSER IS SET: " << pguser << std::endl;
        } else {
            // PGUSER environment variable is not set.
            std::cout << "PGUSER is not set" << std::endl;
            exit(1);
        }

        db.reset(new odb::pgsql::database(pguser, pgpass,
                    DBName, DBHost, DBPort));
        t = new odb::transaction(db->begin());

        main_files = parse_commas_strings(MainFileList);

        // get bug info for the injections we are supposed to be doing.
        debug(INJECT) << "LavaBugList: [" << LavaBugList << "]\n";

        std::set<uint32_t> bug_ids = parse_commas<uint32_t>(LavaBugList);
        // for each bug_id, load that bug from DB and insert into bugs vector.
        std::transform(bug_ids.begin(), bug_ids.end(), std::back_inserter(bugs),
                [&](uint32_t bug_id) { return db->load<Bug>(bug_id); });

        for (const Bug *bug : bugs) {
            LavaASTLoc atp_loc = bug->atp->loc;
            auto key = std::make_pair(atp_loc, bug->atp->type);
            bugs_with_atp_at[key].push_back(bug);

            mark_for_siphon(bug->trigger);

            if (bug->type != Bug::RET_BUFFER) {
                for (uint64_t dua_id : bug->extra_duas) {
                    const DuaBytes *dua_bytes = db->load<DuaBytes>(dua_id);
                    mark_for_siphon(dua_bytes);
                }
            }
        }
    }

    debug(INJECT) << "about to call Tool.run \n";
    LavaMatchFinder Matcher;
    Tool.run(newFrontendActionFactory(&Matcher, &Matcher).get());
    debug(INJECT) << "back from calling Tool.run \n";

    if (LavaAction == LavaQueries) {
        std::cout << "num taint queries added " << num_taint_queries << "\n";
        std::cout << "num atp queries added " << num_atp_queries << "\n";

        if (LavaDB != "XXX") SaveDB(StringIDs, LavaDB);
    } else if (LavaAction == LavaInjectBugs) {
        // TODO this logic is flawed, bugs can be injected across files/directories
        // and this is specific to one single run of lavaTool
        if (!bugs_with_atp_at.empty()) {
            std::cout << "Warning: Failed to inject ATPs in the provided files for the following bug(s):\n";
            for (const auto &keyvalue : bugs_with_atp_at) {
                std::cout << "    At " << keyvalue.first.first << "\n";
                for (const Bug *bug : keyvalue.second) {
                    std::cout << "        " << *bug << "\n";
                }
            }

            std::cout << "Failed bugs IDs: ";
            for (const auto &keyvalue : bugs_with_atp_at) {
                for (const Bug *bug : keyvalue.second) {
                    std::cout << bug->id << ",";
                }
            }
            std::cout << std::endl;
        }
        if (!siphons_at.empty()) {
            std::cout << "Warning: Failed to inject DUA siphons in the provided files for the following bug(s):\n";
            for (const auto &keyvalue : siphons_at) {
                std::cout << "    At " << keyvalue.first << "\n";
                // TODO print failed bugs for siphons as well
                for (const LvalBytes &lval_bytes : keyvalue.second) {
                    std::cout << "        " << lval_bytes << "\n";
                }
            }
        }
    }

    if (t) {
        t->commit();
        delete t;
    }

    return 0;
}
