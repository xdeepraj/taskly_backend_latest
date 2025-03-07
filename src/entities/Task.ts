import { Entity, PrimaryColumn, Column } from "typeorm";

@Entity()
export class Task {
  @Column({ name: "record_id", type: "int", generated: "increment" })
  recordId!: number;

  @PrimaryColumn("uuid")
  task_id!: string;

  @Column({ length: 15 })
  username!: string;

  @Column({ length: 6 })
  task_priority!: string;

  @Column("timestamp")
  datetime!: Date;

  @Column("text")
  task_description!: string;

  @Column()
  is_completed!: boolean;
}
