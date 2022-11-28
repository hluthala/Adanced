﻿// <auto-generated />
using Advanced.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Advanced.Migrations
{
    [DbContext(typeof(DataContext))]
    partial class DataContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "3.1.1")
                .HasAnnotation("Relational:MaxIdentifierLength", 64);

            modelBuilder.Entity("Advanced.Models.Department", b =>
                {
                    b.Property<long>("Departmentid")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    b.Property<string>("Name")
                        .HasColumnType("longtext CHARACTER SET utf8mb4");

                    b.HasKey("Departmentid");

                    b.ToTable("Departments");
                });

            modelBuilder.Entity("Advanced.Models.Location", b =>
                {
                    b.Property<long>("LocationId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    b.Property<string>("City")
                        .HasColumnType("longtext CHARACTER SET utf8mb4");

                    b.Property<string>("State")
                        .HasColumnType("longtext CHARACTER SET utf8mb4");

                    b.HasKey("LocationId");

                    b.ToTable("Locations");
                });

            modelBuilder.Entity("Advanced.Models.Person", b =>
                {
                    b.Property<long>("PersonId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    b.Property<long>("DepartmentId")
                        .HasColumnType("bigint");

                    b.Property<string>("Firstname")
                        .HasColumnType("longtext CHARACTER SET utf8mb4");

                    b.Property<long>("LocationId")
                        .HasColumnType("bigint");

                    b.Property<string>("Surname")
                        .HasColumnType("longtext CHARACTER SET utf8mb4");

                    b.HasKey("PersonId");

                    b.HasIndex("DepartmentId");

                    b.HasIndex("LocationId");

                    b.ToTable("People");
                });

            modelBuilder.Entity("Advanced.Models.Person", b =>
                {
                    b.HasOne("Advanced.Models.Department", "Department")
                        .WithMany("People")
                        .HasForeignKey("DepartmentId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Advanced.Models.Location", "Location")
                        .WithMany("People")
                        .HasForeignKey("LocationId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });
#pragma warning restore 612, 618
        }
    }
}
