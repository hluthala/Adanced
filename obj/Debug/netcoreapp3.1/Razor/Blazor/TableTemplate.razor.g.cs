#pragma checksum "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "028173059b8db5f127b8baff9e9e896db159c1c8"
// <auto-generated/>
#pragma warning disable 1591
namespace Advanced.Blazor
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
    public partial class TableTemplate<RowType> : Microsoft.AspNetCore.Components.ComponentBase
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.OpenElement(0, "div");
            __builder.AddAttribute(1, "class", "container-fluid");
            __builder.AddMarkupContent(2, "\n    ");
            __builder.OpenElement(3, "div");
            __builder.AddAttribute(4, "class", "row");
            __builder.AddMarkupContent(5, "\n        ");
            __builder.OpenElement(6, "div");
            __builder.AddAttribute(7, "class", "col");
            __builder.AddMarkupContent(8, "\n            ");
            __builder.OpenComponent<Advanced.Blazor.SelectFilter>(9);
            __builder.AddAttribute(10, "Title", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.String>(
#nullable restore
#line 6 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                   "Sort"

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(11, "Values", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.Collections.Generic.IEnumerable<System.String>>(
#nullable restore
#line 6 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                                     SortDirectionChoices

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(12, "SelectedValue", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.String>(
#nullable restore
#line 7 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                     SortDirectionSelection

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(13, "SelectedValueChanged", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<Microsoft.AspNetCore.Components.EventCallback<System.String>>(Microsoft.AspNetCore.Components.EventCallback.Factory.Create<System.String>(this, Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.CreateInferredEventCallback(this, __value => SortDirectionSelection = __value, SortDirectionSelection))));
            __builder.CloseComponent();
            __builder.AddMarkupContent(14, "\n        ");
            __builder.CloseElement();
            __builder.AddMarkupContent(15, "\n        ");
            __builder.OpenElement(16, "div");
            __builder.AddAttribute(17, "class", "col");
            __builder.AddMarkupContent(18, "\n            ");
            __builder.OpenComponent<Advanced.Blazor.SelectFilter>(19);
            __builder.AddAttribute(20, "Title", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.String>(
#nullable restore
#line 10 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                   "Highlight"

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(21, "Values", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.Collections.Generic.IEnumerable<System.String>>(
#nullable restore
#line 10 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                                          HighlightChoices()

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(22, "SelectedValue", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<System.String>(
#nullable restore
#line 11 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                     HighlightSelection

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(23, "SelectedValueChanged", Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.TypeCheck<Microsoft.AspNetCore.Components.EventCallback<System.String>>(Microsoft.AspNetCore.Components.EventCallback.Factory.Create<System.String>(this, Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.CreateInferredEventCallback(this, __value => HighlightSelection = __value, HighlightSelection))));
            __builder.CloseComponent();
            __builder.AddMarkupContent(24, "\n        ");
            __builder.CloseElement();
            __builder.AddMarkupContent(25, "\n    ");
            __builder.CloseElement();
            __builder.AddMarkupContent(26, "\n");
            __builder.CloseElement();
            __builder.AddMarkupContent(27, "\n\n");
            __builder.OpenElement(28, "table");
            __builder.AddAttribute(29, "class", "table table-sm table-bordered table-striped");
            __builder.AddMarkupContent(30, "\n");
#nullable restore
#line 17 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
     if (Header != null) {

#line default
#line hidden
#nullable disable
            __builder.AddContent(31, "        ");
            __builder.OpenElement(32, "thead");
            __builder.AddContent(33, 
#nullable restore
#line 18 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                Header

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(34, "\n");
#nullable restore
#line 19 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
    }

#line default
#line hidden
#nullable disable
            __builder.AddContent(35, "    ");
            __builder.OpenElement(36, "tbody");
            __builder.AddMarkupContent(37, "\n");
#nullable restore
#line 21 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
         foreach (RowType item in SortedData()) {

#line default
#line hidden
#nullable disable
            __builder.AddContent(38, "            ");
            __builder.OpenElement(39, "tr");
            __builder.AddAttribute(40, "class", 
#nullable restore
#line 22 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                        IsHighlighted(item)

#line default
#line hidden
#nullable disable
            );
            __builder.AddContent(41, 
#nullable restore
#line 22 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
                                              RowTemplate(item)

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(42, "\n");
#nullable restore
#line 23 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
        }

#line default
#line hidden
#nullable disable
            __builder.AddContent(43, "    ");
            __builder.CloseElement();
            __builder.AddMarkupContent(44, "\n");
            __builder.CloseElement();
        }
        #pragma warning restore 1998
#nullable restore
#line 27 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/TableTemplate.razor"
       
    [Parameter]
    public RenderFragment Header { get; set; }

    [Parameter]
    public RenderFragment<RowType> RowTemplate{ get; set; }

    [Parameter]
    public IEnumerable<RowType> RowData { get; set; }

    [Parameter]
    public Func<RowType, string> Highlight { get; set; }

    public IEnumerable<string> HighlightChoices() =>
        RowData.Select(item => Highlight(item)).Distinct();

    public string HighlightSelection { get; set; }

    public string IsHighlighted(RowType item) =>
        Highlight(item) == HighlightSelection ? "bg-dark text-white": "";

    [Parameter]
    public Func<RowType, string> SortDirection { get; set; }

    public string[] SortDirectionChoices =
        new string[] { "Ascending", "Descending" };

    public string SortDirectionSelection{ get; set; } = "Ascending";

    public IEnumerable<RowType> SortedData() =>
        SortDirectionSelection == "Ascending"
            ? RowData.OrderBy(SortDirection)
            : RowData.OrderByDescending(SortDirection);

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591