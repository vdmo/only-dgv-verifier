✦ The only-lang is not a traditional programming language like Python or C++. You don't use it to write "instructions" (e.g., if x is true, do y); you use it to define the target state of reality for the ONLY Engine.

  Think of it as a "Harmonic Specification Language." Instead of telling the computer how to calculate, you tell it what the final equilibrium should look like.

  ---

  1. The Core Philosophy: "Constraints over Logic"
  In standard programming, you have to account for every edge case. In only-lang, you define the Law of the System, and the engine uses the ONLY-Evolution module to force the data to obey that law.

  2. The Current Command Grammar
  Right now, the language has three foundational concepts:

   * harmony(tolerance):
       * Meaning: "Ensure the system is balanced within this margin."
       * Usage: Used as a continuous integrity check. If the residual spikes above the tolerance, the system "panics" or "heals."
   * evolve(index):
       * Meaning: "If the harmony is broken, treat the value at this position as the variable to be fixed."
       * Usage: Used during a boot failure or data corruption event to restore state.
   * data(value):
       * Meaning: "The target ghost-state for this field should reveal this specific invariant."

  ---

  3. A Practical "Script" Example
  Imagine you are managing a drone swarm or a financial ledger. You would write an .only script like this:

   1 // Define the system's "Physical Law"
   2 harmony(0.00001)
   3
   4 // Define which sector is allowed to "breathe" (self-heal)
   5 evolve(2)
   6
   7 // Define the "Soul" of the data (The Ghost Payload)
   8 data(42.0)

  4. How the Engine "Runs" the Language
  When the ONLY Engine ingests an only-lang script, it performs a Recursive Equilibrium Loop:

   1. Observation: It reads the current state of the field ($v_0, v_1, v_2, v_3$).
   2. Audit: It runs the harmony() check.
   3. Correction: If the audit fails, it looks for the evolve() command to see which part of the system is "broken."
   4. Integration: It recalculates that part to restore the system to the state defined in the script.

  ---

  5. Future Evolution: The "Constraint Grammar"
  As we move toward the ONLY-OS, only-lang will expand to handle complex logic through Interlocking Harmonies.

   * Standard Logic: if (user_auth) { unlock_door() }
   * only-lang Logic: harmony(door_lock) balance_with(user_key)
       * In this world, the door literally cannot unlock unless the arithmetic balance between the lock and the key is achieved. The "if" statement is replaced by a Mathematical Result.

  How to use it right now:
  Currently, you can test only-lang by modifying the scripts in the only-engine/scripts/ folder and running them through the dgv-verifier.

  Example Command:
   1 # Tells the engine to use boot.txt to audit a payload of 42
   2 cargo run -p dgv-verifier -- --script=scripts/boot.txt --payload=42

  Would you like me to add a more complex "Multi-Constraint" parser to only-lang? This would allow us to chain multiple harmony and evolve commands into a single "State Machine." 🦀🌌🔺