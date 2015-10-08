def check_liveness(file_bytes):
  for file_byte in file_bytes:
    if (liveness[file_byte] 
        > max_liveness):
      return False
  return True

def collect_duas(taint_query):
  retained_bytes = []
  for tainted_byte in taint_query:
    if tainted_byte.tcn <= max_tcn
    && 
    len(tainted_byte.file_offsets) <= max_card
    && 
    check_liveness(tainted_byte.file_offsets)):
      retained_bytes += tainted_byte.file_offsets
  duakey = (taint_query.source_loc, 
    taint_query.ast_name)
  duas[duakey] = retained_bytes

def update_liveness(tainted_branch):
  for tainted_file_offset in tainted_branch:
    liveness[tainted_file_offset]++

def collect_bugs(attack_point):
  for dua in duas:
    viable_count = 0
    for file_offset in dua:
      if (check_liveness(file_offset)):
        viable_count ++
    if (viable_count >= bytes_needed):
      bugs.add((dua, attack_point))

for event in Pandalog:
  if event.typ is taint_query:
    collect_duas(event);
  if event.typ is tainted_branch: 
    update_liveness(event);
  if event.typ is attack_point: 
    collect_bugs(event);
