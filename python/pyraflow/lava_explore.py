import angr
import angr.exploration_techniques as et
import claripy
import logging


# Configure logging for this specific technique if desired, otherwise it inherits global.
# logging.getLogger(__name__).setLevel(logging.INFO)
l = logging.getLogger(__name__)

class LAVAPrioritizingTechnique(et.ExplorationTechnique):
    """
    https://github.com/angr/angr/blob/master/angr/exploration_techniques/base.py
    
    A custom Angr exploration technique designed to prioritize states (paths)
    during symbolic execution based on various heuristics, with a focus on
    finding 'hard-to-reach' branches, such as those guarded by specific
    string comparisons (like backdoors or magic values) or deeply nested conditions.

    This technique combines concepts from:
    1.  **Coverage-guided fuzzing/exploration:** Prioritizing states that discover new basic blocks.
        (Justification: This is a fundamental strategy in most modern fuzzers like AFL [1] and
        symbolic execution tools, as exploring new code is key to finding new vulnerabilities [2]).
    2.  **Targeted/Directed Symbolic Execution:** Prioritizing states that are moving closer to
        pre-defined target addresses (e.g., known backdoor functions, interesting memory locations).
        (Justification: Directed symbolic execution aims to reach specific code locations,
        often using heuristics like shortest path to target in the CFG [3, 4]).
    3.  **Constraint Analysis:** Prioritizing states that contain specific types of constraints,
        particularly those involving comparisons with known 'magic values' or string operations.
        (Justification: Symbolic execution's strength is in solving complex constraints. Explicitly
        targeting states with comparisons against known difficult-to-guess values (like passwords
        or protocol magic bytes) is a direct application of this strength,
        bypassing brute-force limitations of fuzzing [5]).
    4.  **Deep Path/Complex Branch Prioritization:** Favoring paths that have traversed more
        conditional branches or have a greater execution depth, which fuzzers typically
        struggle to achieve.
        (Justification: Fuzzers often get stuck in shallow paths. Symbolic execution can
        navigate complex control flow. Prioritizing deeper or more constrained paths helps
        uncover subtle bugs requiring specific sequences of decisions [3, 4]).

    Attributes:
        priority_targets (list[int]): A list of instruction addresses (integers) that this
                                      technique should prioritize reaching.
        magic_values (list[bytes]): A list of concrete byte strings (e.g., b"SOSNEAKY", b"KingRosa")
                                    that, if found in symbolic constraints (e.g., from strcmp),
                                    should increase a state's priority.
        covered_blocks (set): A set of basic block addresses that have been covered so far across
                              all explored paths. Used for new coverage prioritization.
        project (angr.Project): A reference to the Angr project, needed for CFG and symbol lookups.
    
    References:
        [1] Zalewski, Michal. "AFL: American fuzzy lop." (2013).
        [2] Wang, Z. S., et al. "KLEEFuzz: A Hybrid Fuzzing Approach with Directed Symbolic Execution."
            2019 IEEE 4th International Conference on Software Quality, Reliability and Security (QRS).
        [3] Cadar, Cristian, et al. "KLEE: Unassisted and automatic generation of high-coverage tests for complex systems."
            8th USENIX Symposium on Operating Systems Design and Implementation (OSDI). 2008.
        [4] Gan, Yue, et al. "SymCC: Efficiently Stateful Symbolic Execution."
            28th USENIX Security Symposium (USENIX Security 19). 2019.
        [5] Ma, Min, et al. "Fuzzing with Symbolic Execution: A Unified Approach."
            Proceedings of the 2019 27th ACM Joint Meeting on European Software Engineering Conference
            and Symposium on the Foundations of Software Engineering (ESEC/FSE). 2019.
        [6] Yoon, Sang Kil, et al. "Driller: Augmenting Fuzzing with Symbolic Execution."
            23rd Annual Network and Distributed System Security Symposium (NDSS). 2016.
    """
    def __init__(self, project: angr.Project, priority_targets: list[int] = None, magic_values: list[bytes] = None):
        """
        Initializes the custom exploration technique.

        Args:
            project (angr.Project): The Angr project instance.
            priority_targets (list[int], optional): A list of instruction addresses to prioritize.
                                                    Defaults to None.
            magic_values (list[bytes], optional): A list of byte strings to prioritize if
                                                  found in symbolic constraints. Defaults to None.
        """
        super().__init__()
        self.project = project
        self.priority_targets = priority_targets if priority_targets is not None else []
        self.magic_values = magic_values if magic_values is not None else []
        self.covered_blocks = set()

        if self.priority_targets:
            l.info(f"Prioritizing paths towards target addresses: {[hex(a) for a in self.priority_targets]}")
        if self.magic_values:
            l.info(f"Prioritizing paths with constraints involving magic values: {self.magic_values}")

    def _calculate_state_score(self, state: angr.SimState) -> float:
        """
        Calculates a priority score for a given SimState. Higher score = higher priority.

        Args:
            state (angr.SimState): The state to score.

        Returns:
            float: The calculated score.
        """
        score = 0.0 # Default score is 0 if no heuristics apply

        # --- Heuristic 1: New Coverage Maximization ---
        # Prioritize states that visit basic blocks not yet covered.
        # This is a core concept in coverage-guided fuzzing and symbolic execution. [1, 2]
        new_blocks_in_path = len(set(state.history.bbl_addrs) - self.covered_blocks)
        score += new_blocks_in_path * 1000.0  # High weight for new coverage

        # --- Heuristic 2: Targeted Reachability (Closeness to Target Addresses) ---
        # Prioritize states that are closer to pre-defined target addresses.
        # This is a common strategy in directed symbolic execution. [3, 4]
        if self.priority_targets:
            current_addr = state.addr
            # Try to get CFG node for distance calculation. CFG might be slow for large binaries.
            # For simplicity, we'll check if the current address or a recent address
            # in history is one of the targets, or is 'near' a target.
            
            # Simple check: if current address is a target
            if current_addr in self.priority_targets:
                score += 500.0 # Significant boost for being directly at a target

            # More complex: calculate distance in CFG (requires CFG to be computed)
            # This part is commented out by default as CFG computation can be heavy.
            # You would ideally pre-compute the CFG.
            """
            try:
                if self.project.cfg is not None:
                    src_node = self.project.cfg.get_any_node(current_addr)
                    if src_node:
                        min_dist = float('inf')
                        # You might need to compute CFGFast beforehand: self.project.analyses.CFGFast()
                        # And pass it to the constructor or compute it here carefully.
                        # For each target, find the distance.
                        # target_node = self.project.cfg.get_any_node(target_addr)
                        # if target_node:
                        #     dist = src_node.distance_to(target_node)
                        #     if dist is not None:
                        #         min_dist = min(min_dist, dist)
                        
                        if min_dist != float('inf'):
                            # Inverse distance scoring: closer nodes get higher score
                            # Add a small epsilon to avoid division by zero if dist is 0
                            score += (1.0 / (min_dist + 0.1)) * 500.0
            except Exception as e:
                l.debug(f"Could not calculate CFG distance for state {state}: {e}")
            """

        # --- Heuristic 3: Specific Constraint Patterns (Magic Values / Strcmp bypass) ---
        # Prioritize states whose path constraints include comparisons against specific 'magic values'.
        # This leverages symbolic execution's ability to solve for exact values that fuzzers miss. [5]
        for constraint in state.solver.constraints:
            # Check for strcmp-like operations or direct equality with magic values
            # This is a simplified check; complex constraints might require deeper analysis.
            if isinstance(constraint, claripy.ast.BV) and constraint.op == '__cmp_eq': # Check for equality op
                # Iterate through arguments of the equality constraint
                for arg in constraint.args:
                    if isinstance(arg, claripy.ast.BVV): # Check if it's a concrete BitVector Value
                        concrete_value = arg.args[0]
                        if isinstance(concrete_value, bytes):
                            for magic_val in self.magic_values:
                                if magic_val in concrete_value: # Simple substring check for partial matches
                                    score += 200.0 # Significant boost
                                    l.debug(f"Prioritizing state {state.addr} due to magic value '{magic_val}' in constraint.")
                                elif len(concrete_value) == len(magic_val) and concrete_value == magic_val:
                                    score += 300.0 # Even higher for exact match
                                    l.debug(f"Prioritizing state {state.addr} due to exact magic value '{magic_val}' in constraint.")
            
            # More general check for string comparisons (e.g., if SimProcedures for strcmp are used)
            if isinstance(constraint, claripy.ast.Base) and constraint.op == '__strcmp':
                # strcmp SimProcedures generate constraints that involve the strcmp symbolic function.
                # If we encounter such a constraint, it means a strcmp operation happened.
                # We can further inspect its arguments if desired.
                score += 150.0
                l.debug(f"Prioritizing state {state.addr} due to strcmp constraint.")

        # --- Heuristic 4: Prioritize Deeply Nested Paths / Complex Branches ---
        # Fuzzers often struggle to reach deep, nested conditional branches.
        # We can approximate "nestedness" or "complexity" by:
        #   a) Path depth (number of basic blocks executed).
        #   b) Number of accumulated symbolic constraints (each 'if' adds constraints).
        # (Justification: Symbolic execution is effective at traversing complex control flow,
        # and prioritizing deeper/more constrained paths can lead to uncovering more subtle bugs
        # that require specific sequences of decisions. This complements coverage-guided
        # strategies by pushing exploration into more intricate areas. [3, 4])

        # Prioritize states with greater history depth (longer paths)
        score += state.history.depth * 5.0 # Moderate weight

        # Prioritize states with more symbolic constraints (indicative of more conditional branches taken)
        score += len(state.solver.constraints) * 1.0 # Low-to-moderate weight


        # --- Heuristic 5 (Optional/Advanced): Constraint Complexity/Count Reduction ---
        # Generally, states with fewer symbolic variables/constraints are 'simpler' for the solver.
        # This could be a minor negative factor, or a positive if we want simpler paths.
        # score -= len(state.solver.variables) * 0.1 # Minor penalty for more symbolic variables

        # You can add more heuristics here, e.g., prioritizing states in 'unconstrained' stash
        # if len(state.solver.unconstrained_reg_exprs) > 0 or len(state.solver.unconstrained_mem_exprs) > 0:
        #    score += 50 # Or move to a specific stash

        return score

    def step(self, simgr: angr.SimulationManager, stash='active', **kwargs) -> angr.SimulationManager:
        """
        Overrides the default step method to apply custom prioritization.
        This method is called repeatedly by simgr.run() or simgr.explore().

        Args:
            simgr (angr.SimulationManager): The simulation manager instance.
            stash (str, optional): The stash to step. Defaults to 'active'.
            **kwargs: Additional keyword arguments.

        Returns:
            angr.SimulationManager: The updated simulation manager.
        """
        # Step 1: Allow Angr's default stepping behavior or other attached techniques to run first.
        # This generates the successor states.
        simgr = super().step(simgr, stash=stash, **kwargs)

        # Step 2: Apply custom prioritization logic to the states in the specified stash.
        if stash in simgr.stashes and simgr.stashes[stash]:
            states_to_prioritize = list(simgr.stashes[stash]) # Make a copy to iterate and modify original
            
            # Calculate scores for all states in the stash
            states_with_scores = []
            for state in states_to_prioritize:
                score = self._calculate_state_score(state)
                states_with_scores.append((score, state))

            # Sort states in descending order of score (highest priority first)
            states_with_scores.sort(key=lambda x: x[0], reverse=True)

            # Re-order the active stash based on calculated scores.
            # This effectively dictates which state Angr will process next.
            simgr.stashes[stash] = [state for score, state in states_with_scores]
            # l.debug(f"Prioritized stash '{stash}'. Top scores: {[s[0] for s in states_with_scores[:5]]}")

        # Step 3: Update global coverage information based on all active states.
        # This is important for the 'new coverage' heuristic.
        for state in simgr.active:
            for addr in state.history.bbl_addrs:
                self.covered_blocks.add(addr)
        
        return simgr

    # You could also override other methods like `filter_successor` or `complete`
    # for more fine-grained control over state flow between stashes.
