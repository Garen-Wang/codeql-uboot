import cpp

from Function f, FunctionCall fc
where
  fc.getTarget() = f and 
  f.getName() = "memcpy"
select fc