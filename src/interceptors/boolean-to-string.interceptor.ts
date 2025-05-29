import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { map } from 'rxjs/operators';
import { Observable } from 'rxjs';

@Injectable()
export class BooleanToStringInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => this.transformBooleans(data)),
    );
  }

  private transformBooleans(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map((item) => this.transformBooleans(item));
    } else if (obj !== null && typeof obj === 'object') {
      const transformed = {};
      for (const key in obj) {
        if (typeof obj[key] === 'boolean') {
          // Excepción: no transformar el campo 'success'
          if (key === 'success') {
            transformed[key] = obj[key];
          } else {
            transformed[key] = obj[key] ? 'Sí' : 'No';
          }
        } else if (typeof obj[key] === 'object') {
          transformed[key] = this.transformBooleans(obj[key]);
        } else {
          transformed[key] = obj[key];
        }
      }
      return transformed;
    }
    return obj;
  }
}
