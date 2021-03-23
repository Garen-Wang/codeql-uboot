import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists (MacroInvocation inv | 
      inv.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and 
      this = inv.getExpr()
    )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"
