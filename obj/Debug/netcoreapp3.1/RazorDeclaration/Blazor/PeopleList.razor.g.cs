#pragma checksum "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/PeopleList.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "dcf0c6308de9f552d4ae02ae16f3581d5b97078c"
// <auto-generated/>
#pragma warning disable 1591
#pragma warning disable 0414
#pragma warning disable 0649
#pragma warning disable 0169

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
    [Microsoft.AspNetCore.Components.RouteAttribute("/")]
    [Microsoft.AspNetCore.Components.RouteAttribute("/people")]
    public partial class PeopleList : Microsoft.AspNetCore.Components.ComponentBase
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
        }
        #pragma warning restore 1998
#nullable restore
#line 26 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/PeopleList.razor"
       

    [Inject]
    public DataContext Context { get; set; }

    public IEnumerable<Person> People => Context.People
            .Include(p => p.Department)
            .Include(p => p.Location);

    public string GetEditUrl(long id) => $"/person/{id}";

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591
