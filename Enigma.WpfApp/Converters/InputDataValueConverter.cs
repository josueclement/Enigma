using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Markup;
using Enigma.Extensions;
using Enigma.WpfApp.Controls;

namespace Enigma.WpfApp.Converters;

public class InputDataValueConverter : MarkupExtension, IMultiValueConverter
{
    private InputDataTypeItem? _inputDataTypeItem;
    
    public override object? ProvideValue(IServiceProvider serviceProvider)
    {
        return this;
    }

    public object? Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        // var value = (byte[])values[0];
        _inputDataTypeItem = (InputDataTypeItem)values[1];
        
        if (values[0] is byte[] bytes)
            return bytes.ToHexString();
        return null;
    }

    public object?[]? ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
    {
        if (value is string s)
            return [s.FromHexString(), _inputDataTypeItem];
        return [null, _inputDataTypeItem];
    }
}