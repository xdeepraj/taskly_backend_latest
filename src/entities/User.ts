import { Entity, PrimaryColumn, Column } from "typeorm";

@Entity()
export class User {
  @Column({ name: "record_id", type: "int", generated: "increment" })
  recordId!: number;

  @Column({ length: 15 })
  firstname!: string;

  @Column({ length: 30 })
  lastname!: string;

  @Column({ length: 15, unique: true })
  username!: string;

  @PrimaryColumn({ length: 30 })
  email!: string;

  @Column("text")
  password!: string;

  @Column("text")
  refreshToken!: string;
}
