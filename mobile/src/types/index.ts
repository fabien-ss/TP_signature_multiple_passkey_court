export interface DocumentSummary {
  id: number;
  group_id: string;
  version: number;
  title: string;
  status: "PENDING" | "PARTIAL" | "COMPLETE";
  sha256_hash: string;
  created_at: string;
}

export interface SignatureInfo {
  id: number;
  signer: number;
  signer_username: string;
  document_hash: string;
  valid: boolean;
  created_at: string;
}

export interface SignatoryInfo {
  id: number;
  user: number;
  username: string;
  required: boolean;
}

export interface DocumentDetail extends DocumentSummary {
  owner: number;
  updated_at: string;
  signatories: SignatoryInfo[];
  signatures: SignatureInfo[];
  file_url: string;
}
