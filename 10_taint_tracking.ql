import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists (MacroInvocation inv | 
      inv.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and 
      this = inv.getExpr()
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() {
    this = "Network2MemFuncLength"
  }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      sink.asExpr() = fc.getArgument(2) and 
      fc.getTarget().hasQualifiedName("memcpy")
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memory"