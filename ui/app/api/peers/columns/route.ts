import { UColumnsResponse } from '@/app/dto/PeersDTO';
import { TableColumnsResponse } from '@/grpc_generated/route';
import { GetFlowHttpAddressFromEnv } from '@/rpc/http';

export async function POST(request: Request) {
  const body = await request.json();
  const { peerName, schemaName, tableName } = body;
  const flowServiceAddr = GetFlowHttpAddressFromEnv();
  const columnsList: TableColumnsResponse = await fetch(
    `${flowServiceAddr}/v1/peers/columns?peer_name=${peerName}&schema_name=${schemaName}&table_name=${tableName}`
  ).then((res) => res.json());
  let response: UColumnsResponse = {
    columns: columnsList.columns,
  };
  return new Response(JSON.stringify(response));
}
