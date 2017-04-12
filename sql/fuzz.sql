SELECT bug.id as bug, trigger, extra_duas, atp,
    dbt.all_labels as tr_bytes,
    dbe1.all_labels as extra1_bytes,
    attackpoint.loc_filename as file,
    attackpoint.loc_begin_line as line
    FROM bug
    JOIN duabytes dbt on trigger = dbt.id
    JOIN duabytes dbe1 on extra_duas[1] = dbe1.id
    JOIN attackpoint on atp = attackpoint.id
    ORDER BY bug;
