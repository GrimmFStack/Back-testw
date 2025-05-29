export interface JwtPayload {
  sub: number;    
  email: string;  
  is_active: boolean;
  iat?: number;   
  exp?: number;   
}