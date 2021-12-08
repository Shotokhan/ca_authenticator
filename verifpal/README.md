# Crypto assessment

We did an assessment of our custom authentication protocol both "manually", both with a formal verification method, which employed Verifpal. <br>
We described the entire authentication protocol in authN_protocol.vp, but to avoid state-space explosion for symbolic execution, we also created an optimized version. <br>
The run is very fast using verifpal binary (~8200 deductions) and the active attacker finds no ways to exploit the protocol.
 
