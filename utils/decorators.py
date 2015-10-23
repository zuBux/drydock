def assign_order(order):
  def assign(func):
    func.order = order
    return func
  return assign