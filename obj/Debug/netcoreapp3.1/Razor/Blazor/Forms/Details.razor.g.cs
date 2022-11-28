#pragma checksum "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "950bf1e17c156e372c89c3d58b733334735d011a"
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
    [Microsoft.AspNetCore.Components.RouteAttribute("/forms/details/{id:long}")]
    public partial class Details : OwningComponentBase<DataContext>
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.AddMarkupContent(0, "<h4 class=\"bg-info text-center text-white p-2\">Details</h4>\n\n");
            __builder.OpenElement(1, "div");
            __builder.AddAttribute(2, "class", "form-group");
            __builder.AddMarkupContent(3, "\n    ");
            __builder.AddMarkupContent(4, "<label>ID</label>\n    ");
            __builder.OpenElement(5, "input");
            __builder.AddAttribute(6, "class", "form-control");
            __builder.AddAttribute(7, "value", 
#nullable restore
#line 9 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                                        PersonData.PersonId

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(8, "disabled", true);
            __builder.CloseElement();
            __builder.AddMarkupContent(9, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(10, "\n");
            __builder.OpenElement(11, "div");
            __builder.AddAttribute(12, "class", "form-group");
            __builder.AddMarkupContent(13, "\n    ");
            __builder.AddMarkupContent(14, "<label>Firstname</label>\n    ");
            __builder.OpenElement(15, "input");
            __builder.AddAttribute(16, "class", "form-control");
            __builder.AddAttribute(17, "value", 
#nullable restore
#line 13 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                                        PersonData.Firstname

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(18, "disabled", true);
            __builder.CloseElement();
            __builder.AddMarkupContent(19, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(20, "\n");
            __builder.OpenElement(21, "div");
            __builder.AddAttribute(22, "class", "form-group");
            __builder.AddMarkupContent(23, "\n    ");
            __builder.AddMarkupContent(24, "<label>Surname</label>\n    ");
            __builder.OpenElement(25, "input");
            __builder.AddAttribute(26, "class", "form-control");
            __builder.AddAttribute(27, "value", 
#nullable restore
#line 17 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                                        PersonData.Surname

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(28, "disabled", true);
            __builder.CloseElement();
            __builder.AddMarkupContent(29, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(30, "\n");
            __builder.OpenElement(31, "div");
            __builder.AddAttribute(32, "class", "form-group");
            __builder.AddMarkupContent(33, "\n    ");
            __builder.AddMarkupContent(34, "<label>Department</label>\n    ");
            __builder.OpenElement(35, "input");
            __builder.AddAttribute(36, "class", "form-control");
            __builder.AddAttribute(37, "value", 
#nullable restore
#line 21 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                                        PersonData.Department?.Name

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(38, "disabled", true);
            __builder.CloseElement();
            __builder.AddMarkupContent(39, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(40, "\n");
            __builder.OpenElement(41, "div");
            __builder.AddAttribute(42, "class", "form-group");
            __builder.AddMarkupContent(43, "\n    ");
            __builder.AddMarkupContent(44, "<label>Location</label>\n    ");
            __builder.OpenElement(45, "input");
            __builder.AddAttribute(46, "class", "form-control");
            __builder.AddAttribute(47, "value", 
#nullable restore
#line 26 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                    $"{PersonData.Location?.City}, {PersonData.Location?.State}"

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(48, "disabled", true);
            __builder.CloseElement();
            __builder.AddMarkupContent(49, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(50, "\n");
            __builder.OpenElement(51, "div");
            __builder.AddAttribute(52, "class", "text-center");
            __builder.AddMarkupContent(53, "\n    ");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Routing.NavLink>(54);
            __builder.AddAttribute(55, "class", "btn btn-info");
            __builder.AddAttribute(56, "href", 
#nullable restore
#line 30 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
                                         EditUrl

#line default
#line hidden
#nullable disable
            );
            __builder.AddAttribute(57, "ChildContent", (Microsoft.AspNetCore.Components.RenderFragment)((__builder2) => {
                __builder2.AddContent(58, "Edit");
            }
            ));
            __builder.CloseComponent();
            __builder.AddMarkupContent(59, "\n    ");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Routing.NavLink>(60);
            __builder.AddAttribute(61, "class", "btn btn-secondary");
            __builder.AddAttribute(62, "href", "/forms");
            __builder.AddAttribute(63, "ChildContent", (Microsoft.AspNetCore.Components.RenderFragment)((__builder2) => {
                __builder2.AddContent(64, "Back");
            }
            ));
            __builder.CloseComponent();
            __builder.AddMarkupContent(65, "\n");
            __builder.CloseElement();
        }
        #pragma warning restore 1998
#nullable restore
#line 34 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/Details.razor"
       

    [Inject]
    public NavigationManager NavManager { get; set; }

    DataContext Context => Service;

    [Parameter]
    public long Id { get; set; }

    public Person PersonData { get; set; } = new Person();

    protected async override Task OnParametersSetAsync() {
        PersonData = await Context.People.Include(p => p.Department)
            .Include(p => p.Location).FirstOrDefaultAsync(p => p.PersonId == Id);
    }

    public string EditUrl => $"/forms/edit/{Id}";

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591