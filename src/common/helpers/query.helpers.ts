export function applyDefaultOrder(query: any = {}): any {
  return {
    ...query,
    order: [['createdAt', 'DESC']],
  };
}