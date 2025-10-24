namespace SharpEDRChecker
{
    internal interface IChecker
    {
        string Name { get; }
        string Check();
    }
}
