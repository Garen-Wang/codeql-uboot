import cpp

from MacroInvocation inv
where
  inv.getMacro().getName() in ["ntohs", "ntohl", "ntohll"]
select inv.getExpr()