import { IsNotEmpty, IsString } from 'class-validator';
import { LoginRequest } from '../interface/auth';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto implements LoginRequest {
  @ApiProperty({ description: 'User password', required: true })
  @IsNotEmpty()
  @IsString()
  password: string;

  @ApiProperty({ description: 'User email or username', required: true })
  @IsNotEmpty()
  @IsString()
  userNameOrEmail: string;
}
