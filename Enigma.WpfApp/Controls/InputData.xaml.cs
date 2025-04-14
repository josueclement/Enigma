using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;

namespace Enigma.WpfApp.Controls;

public enum InputDataType
{
    Hexadecimal,
    Base64,
    Utf8Text
}

public readonly struct InputDataTypeItem(InputDataType dataType, string displayText)
{
    public InputDataType DataType { get; } = dataType;
    public string DisplayText { get; } = displayText;
}

// public class InputDataValueConverter : IValueConverter
// {
//     public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
//     {
//         return null;
//     }
//
//     public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
//     {
//         return null;
//     }
// }

public partial class InputData : INotifyPropertyChanged
{
    public InputData()
    {
        InitializeComponent();
        DataContext = this;
        
        DataTypes = [
            new InputDataTypeItem(InputDataType.Hexadecimal, "Hexadecimal"),
            new InputDataTypeItem(InputDataType.Base64, "Base64"),
            new InputDataTypeItem(InputDataType.Utf8Text, "UTF-8 Text")
        ];
        SelectedDataType = DataTypes.First();
    }
    
    /// <summary>
    /// Data
    /// </summary>
    [Bindable(true)]
    public byte[] Data
    {
        get => (byte[])GetValue(DataProperty);
        set => SetValue(DataProperty, value);
    }

    /// <summary>
    /// Data property
    /// </summary>
    public static readonly DependencyProperty DataProperty =
        DependencyProperty.Register(name: nameof(Data),
                                    propertyType: typeof(byte[]),
                                    ownerType: typeof(InputData),
                                    typeMetadata: new PropertyMetadata(null, OnDataPropertyChanged));
    
    /// <summary>
    /// Called when <see cref="DataProperty"/> has changed
    /// </summary>
    /// <param name="d">Caller</param>
    /// <param name="e">Event</param>
    private static void OnDataPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((InputData)d).OnDataChanged(e);

    /// <summary>
    /// Called when <see cref="Data"/> has changed
    /// </summary>
    /// <param name="e">Event</param>
    protected virtual void OnDataChanged(DependencyPropertyChangedEventArgs e) { }

    public ObservableCollection<InputDataTypeItem> DataTypes { get; }
        
    
    private InputDataTypeItem? _selectedDataType;
    public InputDataTypeItem? SelectedDataType
    {
        get => _selectedDataType;
        set => SetField(ref _selectedDataType, value);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}