export function formatResponse(records: any[]): any {
  return {
    success: true,
    data: {
      records,
      total_count: records.length,
    },
  };
}
