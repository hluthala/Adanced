#pragma checksum "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4ec9174fcb044ad777dc9b762733a34f580400ab"
// <auto-generated/>
#pragma warning disable 1591
namespace Advanced.Blazor.Forms
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
#nullable restore
#line 1 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Forms;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Routing;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Web;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.JSInterop;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.EntityFrameworkCore;

#line default
#line hidden
#nullable disable
#nullable restore
#line 7 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Advanced.Models;

#line default
#line hidden
#nullable disable
    [Microsoft.AspNetCore.Components.LayoutAttribute(typeof(EmptyLayout))]
    [Microsoft.AspNetCore.Components.RouteAttribute("/forms")]
    [Microsoft.AspNetCore.Components.RouteAttribute("/forms/list")]
    public partial class List : OwningComponentBase<DataContext>
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.AddMarkupContent(0, "<h5 class=\"bg-primary text-white text-center p-2\">People</h5>\n\n");
            __builder.OpenElement(1, "table");
            __builder.AddAttribute(2, "class", "table table-sm table-striped table-bordered");
            __builder.AddMarkupContent(3, "\n    ");
            __builder.AddMarkupContent(4, "<thead>\n        <tr>\n            <th>ID</th><th>Name</th><th>Dept</th><th>Location</th><th></th>\n        </tr>\n    </thead>\n    ");
            __builder.OpenElement(5, "tbody");
            __builder.AddMarkupContent(6, "\n");
#nullable restore
#line 15 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
         if  (People.Count() == 0) {

#line default
#line hidden
#nullable disable
            __builder.AddContent(7, "            ");
            __builder.AddMarkupContent(8, "<tr><th colspan=\"5\" class=\"p-4 text-center\">Loading Data...</th></tr>\n");
#nullable restore
#line 17 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
        } else {
            

#line default
#line hidden
#nullable disable
#nullable restore
#line 18 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
             foreach (Person p in People) {

#line default
#line hidden
#nullable disable
            __builder.AddContent(9, "                ");
            __builder.OpenElement(10, "tr");
            __builder.AddMarkupContent(11, "\n                    ");
            __builder.OpenElement(12, "td");
            __builder.AddContent(13, 
#nullable restore
#line 20 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                         p.PersonId

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(14, "\n                    ");
            __builder.OpenElement(15, "td");
            __builder.AddContent(16, 
#nullable restore
#line 21 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                         p.Surname

#line default
#line hidden
#nullable disable
            );
            __builder.AddContent(17, ", ");
            __builder.AddContent(18, 
#nullable restore
#line 21 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                                     p.Firstname

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(19, "\n                    ");
            __builder.OpenElement(20, "td");
            __builder.AddContent(21, 
#nullable restore
#line 22 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                         p.Department.Name

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(22, "\n                    ");
            __builder.OpenElement(23, "td");
            __builder.AddContent(24, 
#nullable restore
#line 23 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                         p.Location.City

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(25, "\n                    ");
            __builder.OpenElement(26, "td");
            __builder.AddAttribute(27, "class", "text-center");
            __builder.AddMarkupContent(28, "\n                        ");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Routing.NavLink>(29);
            __builder.AddAttribute(30, "class", "btn btn-sm btn-info");
            __builder.AddAttribute(31, "href", 
#nullable restore
#line 26 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                                      GetDetailsUrl(p.PersonId)

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(32, "ChildContent", (Microsoft.AspNetCore.Components.RenderFragment)((__builder2) => {
                __builder2.AddMarkupContent(33, "\n                            Details\n                        ");
            }
            ));
            __builder.CloseComponent();
            __builder.AddMarkupContent(34, "\n                        ");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Routing.NavLink>(35);
            __builder.AddAttribute(36, "class", "btn btn-sm btn-warning");
            __builder.AddAttribute(37, "href", 
#nullable restore
#line 30 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                                      GetEditUrl(p.PersonId)

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(38, "ChildContent", (Microsoft.AspNetCore.Components.RenderFragment)((__builder2) => {
                __builder2.AddMarkupContent(39, "\n                            Edit\n                        ");
            }
            ));
            __builder.CloseComponent();
            __builder.AddMarkupContent(40, "\n                        ");
            __builder.OpenElement(41, "button");
            __builder.AddAttribute(42, "class", "btn btn-sm btn-danger");
            __builder.AddAttribute(43, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 34 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
                                            () => HandleDelete(p)

#line default
#line hidden
#nullable disable
            ));
            __builder.AddMarkupContent(44, "\n                            Delete\n                        ");
            __builder.CloseElement();
            __builder.AddMarkupContent(45, "\n                    ");
            __builder.CloseElement();
            __builder.AddMarkupContent(46, "\n                ");
            __builder.CloseElement();
            __builder.AddMarkupContent(47, "\n");
#nullable restore
#line 39 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
            }

#line default
#line hidden
#nullable disable
#nullable restore
#line 39 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
             
        }

#line default
#line hidden
#nullable disable
            __builder.AddContent(48, "    ");
            __builder.CloseElement();
            __builder.AddMarkupContent(49, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(50, "\n\n");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Routing.NavLink>(51);
            __builder.AddAttribute(52, "class", "btn btn-primary");
            __builder.AddAttribute(53, "href", "/forms/create");
            __builder.AddAttribute(54, "ChildContent", (Microsoft.AspNetCore.Components.RenderFragment)((__builder2) => {
                __builder2.AddContent(55, "Create");
            }
            ));
            __builder.CloseComponent();
        }
        #pragma warning restore 1998
#nullable restore
#line 46 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
       

    public DataContext Context => Service;

    public IEnumerable<Person> People { get; set; } = Enumerable.Empty<Person>();

    protected async override Task OnInitializedAsync() {
        await UpdateData();
    }

    private IQueryable<Person> Query => Context.People.Include(p => p.Department)
            .Include(p => p.Location);

    private async Task UpdateData(IQueryable<Person> query = null) =>
        People = await (query ?? Query).ToListAsync<Person>();

    string GetEditUrl(long id) => $"/forms/edit/{id}";
    string GetDetailsUrl(long id) => $"/forms/details/{id}";

    public async Task HandleDelete(Person p) {
        Context.Remove(p);
        await Context.SaveChangesAsync();
        await UpdateData();
    }

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591
